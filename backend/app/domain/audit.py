"""
Domain Model: Tamper-Evident Audit Trail (Feature 07)
Demonstrates Encapsulation and Data Integrity using Cryptographic Hash Chaining (SHA-256).
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional


class AuditBlock:
    """
    An immutable block in the append-only audit trail.
    """
    def __init__(
        self,
        index: int,
        timestamp: str,
        event_type: str,
        payload: Dict[str, Any],
        previous_hash: str,
        current_hash: Optional[str] = None
    ):
        self.index: int = index
        self.timestamp: str = timestamp
        self.event_type: str = event_type
        self.payload: Dict[str, Any] = payload
        self.previous_hash: str = previous_hash
        self.current_hash: str = current_hash or self.calculate_hash()

    def calculate_hash(self) -> str:
        """Computes SHA-256 checksum over block contents."""
        serialized_payload = json.dumps(self.payload, sort_keys=True)
        raw_string = f"{self.index}:{self.timestamp}:{self.event_type}:{serialized_payload}:{self.previous_hash}"
        return hashlib.sha256(raw_string.encode('utf-8')).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "hash": self.current_hash
        }


class TamperEvidentAuditTrail:
    """
    Append-only verifiable ledger.
    Every payment decision and analyst action is cryptographically anchored.
    """
    GENESIS_HASH = "0" * 64

    def __init__(self):
        self.__chain: List[AuditBlock] = []
        # Create Genesis Block
        genesis = AuditBlock(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="GENESIS",
            payload={"system": "Dhoka Detector v1.0", "market": "Pakistan FinTech"},
            previous_hash=self.GENESIS_HASH
        )
        self.__chain.append(genesis)

    @property
    def chain(self) -> List[AuditBlock]:
        return list(self.__chain)

    def append_event(self, event_type: str, payload: Dict[str, Any]) -> AuditBlock:
        """Appends a new immutable event to the chain."""
        last_block = self.__chain[-1]
        new_block = AuditBlock(
            index=len(self.__chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            payload=payload,
            previous_hash=last_block.current_hash
        )
        self.__chain.append(new_block)
        return new_block

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Validates the cryptographic chain.
        Returns (True, None) if completely intact,
        or (False, "Error description") if tampering is detected.
        """
        for i in range(1, len(self.__chain)):
            current = self.__chain[i]
            previous = self.__chain[i - 1]

            # 1. Verify previous_hash link
            if current.previous_hash != previous.current_hash:
                return (
                    False,
                    f"Broken Link at Block {current.index}: Previous hash {current.previous_hash[:10]}... does not match Block {previous.index} hash {previous.current_hash[:10]}..."
                )

            # 2. Verify hash recalculated from contents
            recalculated_hash = current.calculate_hash()
            if current.current_hash != recalculated_hash:
                return (
                    False,
                    f"Tampered Payload at Block {current.index}: Stored hash {current.current_hash[:10]}... does not match recalculated content hash {recalculated_hash[:10]}..."
                )

        return (True, "Audit trail integrity verified: All blocks cryptographic hashes match.")
