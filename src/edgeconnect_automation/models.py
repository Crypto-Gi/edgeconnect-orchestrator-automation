from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple


PairKey = Tuple[str, str]
ScopeKey = Tuple[str, str, str, str]


@dataclass
class FirewallRule:
    row: int
    rule_key: str
    rule_name: str
    description: str
    enabled: bool
    priority: Optional[int]
    source_segment: str
    destination_segment: str
    source_zone: str
    destination_zone: str
    source_address: str = ""
    source_address_group: str = ""
    destination_address: str = ""
    destination_address_group: str = ""
    either_address: str = ""
    either_address_group: str = ""
    application: str = ""
    application_group: str = ""
    protocol: str = ""
    source_port: str = ""
    destination_port: str = ""
    either_port: str = ""
    source_service_group: str = ""
    destination_service_group: str = ""
    either_service_group: str = ""
    action: str = ""
    logging: bool = False
    logging_level: int = 0
    broad_match_ack: bool = False

    @property
    def pair(self) -> PairKey:
        return self.source_segment, self.destination_segment

    @property
    def scope(self) -> ScopeKey:
        return self.source_segment, self.destination_segment, self.source_zone, self.destination_zone


@dataclass
class Inventory:
    segments: Mapping[str, int]
    zones: Mapping[Tuple[str, str], int]
    policies: Mapping[PairKey, Mapping[str, Any]]
    address_groups: Set[str] = field(default_factory=set)
    service_groups: Set[str] = field(default_factory=set)
    applications: Set[str] = field(default_factory=set)
    application_groups: Set[str] = field(default_factory=set)
    local_priorities: Mapping[ScopeKey, Set[int]] = field(default_factory=dict)
    statuses: Mapping[str, str] = field(default_factory=dict)
    segmentation_enabled: bool = True
    target_states: Mapping[str, str] = field(default_factory=dict)
    pair_errors: Mapping[PairKey, List[str]] = field(default_factory=dict)


@dataclass
class PairPlan:
    pair: PairKey
    segment_map: str
    eligible: bool
    baseline: Mapping[str, Any]
    candidate: Mapping[str, Any]
    baseline_fingerprint: str
    rules: List[FirewallRule] = field(default_factory=list)
    created_priorities: List[Tuple[str, int]] = field(default_factory=list)
    no_op_rows: List[int] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    target_states: Dict[str, str] = field(default_factory=dict)


@dataclass
class FirewallPlan:
    pairs: List[PairPlan]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    resolved_rows: List[FirewallRule] = field(default_factory=list)

    @property
    def eligible_pairs(self) -> List[PairPlan]:
        return [pair for pair in self.pairs if pair.eligible]

    @property
    def has_ineligible_pairs(self) -> bool:
        return any(not pair.eligible for pair in self.pairs)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PairResult:
    pair: PairKey
    status: str
    message: str = ""
    rollback_status: str = "not_needed"
    targets: Dict[str, str] = field(default_factory=dict)


@dataclass
class RunResult:
    status: str
    pairs: List[PairResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    run_reference: str = ""

    @property
    def exit_code(self) -> int:
        return {"SUCCESS": 0, "VALIDATION": 2, "REFUSED": 3, "DRIFT": 4, "PARTIAL": 5, "CRITICAL": 5}.get(self.status, 1)
