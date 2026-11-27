"""
Check 2: DeviceRiskCheck
Evaluates hardware fingerprint/device ID against customer's known trusted devices.
Addresses Instructor Requirement 2: Clearly flags whether device telemetry is simulated.
"""
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class DeviceRiskCheck(RiskCheck):
    def __init__(self, weight: float = 14.0):
        super().__init__(
            name="DeviceRiskCheck",
            weight=weight,
            signal_origin="SIMULATED_TELEMETRY"
        )

    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        device_id = transaction.device_id
        is_known = profile.is_device_known(device_id)

        if is_known:
            return CheckResult(
                check_name=self.name,
                weight=self.weight,
                raw_score=0.0,
                score_contribution=0.0,
                triggered=False,
                signal_origin=self.signal_origin,
                reason=f"Device '{device_id}' recognized in customer's trusted device registry.",
                evidence={"device_id": device_id, "is_known": True}
            )
        else:
            return CheckResult(
                check_name=self.name,
                weight=self.weight,
                raw_score=1.0,
                score_contribution=round(1.0 * self.weight, 2),
                triggered=True,
                signal_origin=self.signal_origin,
                reason=f"Unrecognized device signature '{device_id}'. Transaction initiated from new hardware.",
                evidence={
                    "device_id": device_id,
                    "is_known": False,
                    "trusted_devices_count": len(profile.known_devices)
                }
            )
