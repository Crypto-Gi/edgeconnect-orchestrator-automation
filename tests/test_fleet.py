import socket
import ssl
import threading
import time
import unittest
from urllib.error import URLError

from edgeconnect_automation import fleet
from edgeconnect_automation.errors import AuthenticationError, RateLimitError, ServerError, TransportError

KEY = "<API_KEY>"


def transport(cause):
    error = TransportError("transport failure: {}".format(type(cause).__name__), None, "GET", "/gmsserver/briefInfo")
    error.__cause__ = cause
    return error


class Client:
    """Answers per Orchestrator nickname: a release, a serial number, or an error to raise."""

    answers = {}
    calls = []

    def __init__(self, config):
        self.config = config
        self.answer = type(self).answers[config.name]

    def get(self, path):
        type(self).calls.append((self.config.name, path, self.config.timeout, self.config.max_read_attempts))
        if isinstance(self.answer, Exception):
            raise self.answer
        if path == "/gmsserver/briefInfo":
            if self.answer.get("delay"):
                self.answer["clock"].now += self.answer["delay"]
            return {"release": self.answer.get("release", "9.7.1")}
        return {"serialNumber": self.answer.get("serial", "SERIAL-" + self.config.name)}


class Clock:
    now = 0.0

    def __call__(self):
        return self.now


def environment(*names, **extra):
    env = {"orch_{}".format(number): name for number, name in enumerate(names, 1)}
    for name in names:
        env.update({name + "_base_url": "https://{}.invalid".format(name), name + "_api_key": KEY})
    env.update(extra)
    return env


class FleetStatusTests(unittest.TestCase):
    def setUp(self):
        Client.calls = []
        self.clock = Clock()

    def check(self, env, **answers):
        Client.answers = answers
        return {status.name: status for status in fleet.check_all(dotenv_path="", environ=env, client_factory=Client, clock=self.clock)}

    def test_each_status_with_its_plain_reason(self):
        env = environment("good", "slow", "noserial", "busy", "badkey", "old", "broken", "down", "badcert", "nodns", "refused", "nokey")
        del env["nokey_api_key"]
        result = self.check(
            env,
            good={},
            slow={"delay": 3.0, "clock": self.clock},
            noserial={"serial": ""},
            busy=RateLimitError("HTTP 429", 429),
            badkey=AuthenticationError("HTTP 401", 401),
            old={"release": "9.2.4"},
            broken=ServerError("HTTP 503", 503),
            down=transport(URLError(socket.timeout("timed out"))),
            badcert=transport(URLError(ssl.SSLCertVerificationError("certificate verify failed"))),
            nodns=transport(URLError(socket.gaierror(8, "nodename nor servname provided"))),
            refused=transport(URLError(ConnectionRefusedError(61, "Connection refused"))),
        )
        self.assertEqual({name: (status.status, status.reason) for name, status in result.items()}, {
            "good": ("green", "connected (release 9.7.1)"),
            "slow": ("amber", "connected (release 9.7.1), but slow: 3.0 s to answer"),
            "noserial": ("amber", "connected (release 9.7.1), but the serial number is not readable, so a different Orchestrator at this address would not be noticed"),
            "busy": ("amber", "Orchestrator is busy (HTTP 429); check again shortly"),
            "badkey": ("red", "the API key was refused (HTTP 401)"),
            "old": ("red", "Orchestrator 9.3 or later is required; found 9.2.4"),
            "broken": ("red", "Orchestrator answered with a server error (HTTP 503)"),
            "down": ("red", "no answer within 5 s"),
            "badcert": ("red", "the certificate was not accepted; check the CA bundle or the certificate pin"),
            "nodns": ("red", "the address could not be found (DNS)"),
            "refused": ("red", "the connection was refused"),
            "nokey": ("red", "fix the settings: Orchestrator 'nokey' (orch_12) needs both nokey_base_url and nokey_api_key"),
        })
        self.assertEqual((result["good"].url, result["good"].release, result["good"].id), ("https://good.invalid", "9.7.1", "SERIAL-good"))
        self.assertEqual(list(result), ["good", "slow", "noserial", "busy", "badkey", "old", "broken", "down", "badcert", "nodns", "refused", "nokey"])

    def test_each_read_gets_one_short_try(self):
        self.check(environment("lab"), lab={})
        self.assertEqual(Client.calls, [("lab", "/gmsserver/briefInfo", 5.0, 1), ("lab", "/gmsserver/info", 5.0, 1)])

    def test_all_orchestrators_are_checked_at_the_same_time(self):
        both_asked = threading.Barrier(2, timeout=5)

        class Waiting(Client):
            def get(self, path):
                if path == "/gmsserver/briefInfo":
                    both_asked.wait()
                return super().get(path)

        Client.answers = {"a": {}, "b": {}}
        result = fleet.check_all(dotenv_path="", environ=environment("a", "b"), client_factory=Waiting)
        self.assertEqual([status.status for status in result], ["green", "green"])

    def test_gui_label_colour_and_writes_switch(self):
        env = environment("lab", "prod", "badcolor", "badwrites", lab_gui_label="Lab", lab_gui_color="#1F6FEB", lab_gui_writes="on", badcolor_gui_color="red", badwrites_gui_writes="maybe")
        result = self.check(env, lab={}, prod={}, badcolor={}, badwrites={})
        self.assertEqual((result["lab"].label, result["lab"].color, result["lab"].writes), ("Lab", "#1F6FEB", True))
        self.assertFalse(result["prod"].writes)  # writes are off unless switched on
        self.assertEqual((result["badcolor"].status, result["badcolor"].reason), ("red", "fix the settings: badcolor_gui_color must be a colour like #1f6feb"))
        self.assertEqual((result["badwrites"].status, result["badwrites"].reason), ("red", "fix the settings: badwrites_gui_writes must be on or off"))

    def test_single_orchestrator_without_nicknames(self):
        result = self.check({"orchestrator_base_url": "https://one.invalid", "orchestrator_api_key": KEY}, **{"": {}})
        self.assertEqual(([status.name for status in result.values()], result[""].status, result[""].url), ([""], "green", "https://one.invalid"))


if __name__ == "__main__":
    unittest.main()
