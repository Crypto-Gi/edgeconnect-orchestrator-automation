import copy
import json
import time
from typing import Any, Dict, Iterable, Mapping, Optional

from .client import ApiClient
from .errors import ResponseFormatError, ValidationError
from .util import semantic_equal


class OrchestratorGateway:
    def __init__(self, client: ApiClient, targets: Optional[Mapping[str, str]] = None) -> None:
        self.client = client
        self.targets = dict(targets or {})

    @staticmethod
    def _shape(value: Any, expected: Any, label: str) -> Any:
        if not isinstance(value, expected):
            raise ResponseFormatError("{} response has an invalid shape".format(label))
        return value

    def get_version(self) -> Mapping[str, Any]:
        return self._shape(self.client.get("/gmsserver/briefInfo"), dict, "Orchestrator version")

    def discover(self) -> Dict[str, Any]:
        return {
            "version": self.get_version(),
            "segmentation": self.client.get("/vrf/config/enable"),
            "segments": self.client.get("/vrf/config/segments"),
            "zones": self.client.get("/zones"),
            "segment_zones": self.client.get("/zones/vrfSegmentZonesMap"),
            "address_groups": self.client.get("/ipObjects/addressGroup"),
            "service_groups": self.client.get("/ipObjects/serviceGroup"),
        }

    def get_segmentation(self) -> Mapping[str, Any]:
        return self._shape(self.client.get("/vrf/config/enable"), dict, "segmentation")

    def get_segments(self) -> Mapping[str, Any]:
        return self._shape(self.client.get("/vrf/config/segments"), dict, "segments")

    def get_segment_zones(self) -> Any:
        return self._shape(self.client.get("/zones/vrfSegmentZonesMap"), list, "segment zones")

    def get_policy(self, segment_map: str) -> Mapping[str, Any]:
        value = self.client.get("/vrf/config/securityPolicies", {"map": segment_map})
        if not isinstance(value, dict):
            raise TypeError("security policy response must be an object")
        return value

    def post_policy(self, segment_map: str, candidate: Mapping[str, Any], comment: str) -> None:
        self.client.post_json(
            "/vrf/config/securityPolicies",
            candidate,
            {"map": segment_map, "comment": comment},
            (204,),
        )

    def verify_targets(self, segment_map: str, candidate: Mapping[str, Any], run_reference: str) -> Dict[str, str]:
        results = {target: state for target, state in self.targets.items() if state != "reachable"}
        pending = {target for target, state in self.targets.items() if state == "reachable"}
        deadline = time.monotonic() + getattr(getattr(self.client, "config", None), "verification_timeout", 120.0)
        while pending and time.monotonic() < deadline:
            for target in list(pending):
                try:
                    value = self.client.get("/securityMaps", {"nePk": target, "cached": "false"})
                except Exception:
                    continue
                if self._effective_contains(value, candidate):
                    results[target] = "verified"
                    pending.remove(target)
            if pending:
                time.sleep(getattr(getattr(self.client, "config", None), "poll_interval", 5.0))
        for target in pending:
            results[target] = "unverified"
        return results

    @staticmethod
    def _effective_contains(effective: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
        expected_maps = candidate.get("data", {}).get("map1", {})
        actual_maps = effective.get("data", {}).get("map1", effective.get("map1", {}))
        for zone_key, container in expected_maps.items():
            actual_rules = actual_maps.get(zone_key, {}).get("prio", {})
            for priority, expected in container.get("prio", {}).items():
                actual = copy.deepcopy(actual_rules.get(priority))
                if actual is None:
                    return False
                actual.get("match", {}).pop("acl", None)
                if "logging_priority" in actual.get("misc", {}):
                    actual["misc"]["logging_priority"] = int(actual["misc"]["logging_priority"])
                if not semantic_equal(actual, expected):
                    return False
        return True

    def get_zones(self) -> Mapping[str, Any]:
        return self._shape(self.client.get("/zones"), dict, "zones")

    def get_all_vrf_zones(self) -> Any:
        return self._shape(self.client.get("/zones", {"allVRFZones": "true"}), (dict, list), "all-VRF zones")

    def get_next_zone_id(self) -> int:
        value = self.client.get("/zones/nextId")
        if isinstance(value, dict):
            value = value.get("nextId")
        return int(value)

    def get_zone_mappings(self) -> Any:
        return self._shape(self.client.get("/zones/vrfSegmentZonesMap"), list, "zone mappings")

    def post_zones(self, zones: Mapping[str, Any]) -> None:
        self.client.post_json("/zones", zones, {"deleteDependencies": "false"}, (204,))

    def get_address_groups(self) -> Any:
        return self._shape(self.client.get("/ipObjects/addressGroup"), list, "address groups")

    def get_service_groups(self) -> Any:
        return self._shape(self.client.get("/ipObjects/serviceGroup"), list, "service groups")

    def upload_address_groups(self, content: bytes) -> Mapping[str, Any]:
        response = self.client.post_multipart_file("/ipObjects/addressGroup/bulkUpload", "csvFile", "address_groups.csv", content)
        return self._bulk_upload_response(response)

    def upload_service_groups(self, content: bytes) -> Mapping[str, Any]:
        response = self.client.post_multipart_file("/ipObjects/serviceGroup/bulkUpload", "csvFile", "service_groups.csv", content)
        return self._bulk_upload_response(response)

    def delete_address_group(self, name: str) -> None:
        self.client.request("DELETE", "/ipObjects/addressGroup", query={"name": name}, expected_status=(200, 204), expect_json=False)

    def delete_service_group(self, name: str) -> None:
        self.client.request("DELETE", "/ipObjects/serviceGroup", query={"name": name}, expected_status=(200, 204), expect_json=False)

    @staticmethod
    def _bulk_upload_response(value: Any) -> Mapping[str, Any]:
        if not isinstance(value, dict) or not isinstance(value.get("success"), bool):
            raise ResponseFormatError("bulk upload response has an invalid shape")
        if not value["success"]:
            message = value.get("error") or value.get("message") or "native bulk import failed"
            raise ValidationError(str(message))
        return value

    def get_application_groups(self) -> Mapping[str, Any]:
        return self._shape(self.client.get("/applicationDefinition/applicationTags", {"resourceKey": "userDefined"}), dict, "application groups")

    def post_application_groups(self, groups: Mapping[str, Any]) -> None:
        self.client.post_json("/applicationDefinition/applicationTags", groups, expected_status=(200, 204))

    def get_application_definitions(self, base: str) -> Any:
        if base not in {"portProtocolClassification", "dnsClassification", "compoundClassification"}:
            raise ValueError("unsupported application definition base")
        value = self.client.get("/applicationDefinition", {"base": base, "resourceKey": "userDefined"})
        expected = list if base == "dnsClassification" else dict
        return self._shape(value, expected, "application definitions")

    def post_application_definition(self, base: str, value: Any, identity: Any) -> None:
        if base == "portProtocolClassification":
            port, protocol = identity
            path = "/applicationDefinition/portProtocolClassification"
            query = {"port": port, "protocol": protocol}
        elif base == "dnsClassification":
            path = "/applicationDefinition/dnsClassification"
            query = {"domain": identity}
        elif base == "compoundClassification":
            path = "/applicationDefinition/compoundClassification"
            query = {"id": identity}
        else:
            raise ValueError("unsupported application definition base")
        self.client.post_json(path, value, query, (200, 204))

    def delete_application_definition(self, base: str, identity: Any) -> None:
        if base == "portProtocolClassification":
            port, protocol = identity
            path = "/applicationDefinition/portProtocolClassification"
            query = {"port": port, "protocol": protocol}
        elif base == "dnsClassification":
            path = "/applicationDefinition/dnsClassification"
            query = {"domain": identity}
        elif base == "compoundClassification":
            path = "/applicationDefinition/compoundClassification"
            query = {"id": identity}
        else:
            raise ValueError("unsupported application definition base")
        self.client.request("DELETE", path, query=query, expected_status=(200, 204), expect_json=False)

    def get_appexpress(self) -> Mapping[str, Any]:
        return self._shape(self.client.get("/applicationDefinition/appExpressAppConfig", {"resourceKey": "userDefined"}), dict, "AppExpress")

    def post_appexpress(self, value: Mapping[str, Any]) -> None:
        self.client.post_json("/applicationDefinition/appExpressAppConfig", value, {"resourceKey": "userDefined"}, (200, 204))

    def search_application(self, name: str) -> Any:
        return self.client.request("POST", "/applicationDefinition/applications/wildcard", json_body={"pattern": name, "limit": 100}, expected_status=(200,), expect_json=True)

    def search_application_group(self, name: str) -> Any:
        return self.client.request("POST", "/applicationDefinition/applicationTags/wildcard", json_body={"pattern": name, "limit": 100}, expected_status=(200,), expect_json=True)

    def get_appliances(self) -> Any:
        return self._shape(self.client.get("/appliance"), list, "appliances")

    def get_paused_orchestration(self) -> Any:
        return self._shape(self.client.get("/pauseOrchestration"), (list, dict), "paused orchestration")

    def get_reachability(self, nepk: str) -> Mapping[str, Any]:
        return self._shape(self.client.get("/reachability/gms", {"nePk": nepk}), dict, "reachability")

    def get_security_map(self, nepk: str) -> Mapping[str, Any]:
        return self._shape(self.client.get("/securityMaps", {"nePk": nepk, "cached": "false"}), dict, "security map")

    def get_actions(self, start_time: int, end_time: int) -> Any:
        return self.client.get("/action", {"startTime": start_time, "endTime": end_time})

    def correlate_audit(self, segment_map: str, run_reference: str) -> bool:
        start_time = int(time.time() * 1000) - 300000
        deadline = time.monotonic() + getattr(getattr(self.client, "config", None), "verification_timeout", 120.0)
        while time.monotonic() < deadline:
            actions = self.get_actions(start_time, int(time.time() * 1000))
            if isinstance(actions, list):
                for action in actions:
                    text = json.dumps(action, sort_keys=True)
                    if run_reference in text and (segment_map in text or "Segment Security Policy Changed" in text):
                        return action.get("taskStatus") == "COMPLETED" and action.get("completionStatus") is True
            time.sleep(getattr(getattr(self.client, "config", None), "poll_interval", 5.0))
        return False
