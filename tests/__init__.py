import os
import tempfile

os.environ.setdefault("EDGECONNECT_REPORT_DIR", tempfile.mkdtemp(prefix="edgeconnect-test-reports-"))
