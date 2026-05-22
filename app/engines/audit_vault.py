"""
AEGIS Audit Vault Engine
Immutable, hash-chained audit logging with cryptographic tamper evidence.

Each audit entry contains:
- Timestamp
- Event type
- Actor (user/system)
- System name (optional)
- Details (JSON)
- SHA-256 hash (includes previous hash)
- Previous entry's hash

Verification: Recompute hash chain from genesis to detect tampering.
"""

import hashlib
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import AuditLog


@dataclass
class AuditEntry:
    """Represents a single audit entry."""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: str = ""
    actor: str = ""
    system_name: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    hash: str = ""
    prev_hash: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "actor": self.actor,
            "system_name": self.system_name,
            "details": self.details,
            "hash": self.hash,
            "prev_hash": self.prev_hash,
        }


@dataclass
class VerificationResult:
    """Result of audit chain verification."""
    verified: bool
    total_entries: int
    first_entry_hash: str
    last_entry_hash: str
    message: str
    tampered_entries: List[int] = field(default_factory=list)


class AuditVault:
    """
    Immutable audit vault with hash-chained entries.
    
    Hash Chain Mechanism:
    - Genesis entry: hash = SHA256(GENESIS_SEED + entry_data)
    - Subsequent entries: hash = SHA256(prev_hash + entry_data)
    
    Verification:
    - Recompute all hashes from genesis
    - Any mismatch indicates tampering
    """
    
    GENESIS_HASH = "GENESIS"
    
    def __init__(self, genesis_seed: str = None):
        """Initialize the audit vault."""
        self.genesis_seed = genesis_seed or settings.audit_genesis_seed
    
    def _compute_hash(self, prev_hash: str, entry_data: Dict[str, Any]) -> str:
        """
        Compute SHA-256 hash for an entry.
        
        Hash = SHA256(prev_hash + canonical_json(entry_data))
        """
        # Create canonical JSON representation (sorted keys, no whitespace)
        canonical_data = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        
        # Combine with previous hash
        hash_input = f"{prev_hash}{canonical_data}"
        
        # Compute SHA-256
        return hashlib.sha256(hash_input.encode()).hexdigest()
    
    def _prepare_entry_data(self, entry: AuditEntry) -> Dict[str, Any]:
        """Prepare entry data for hashing (excludes hash fields)."""
        return {
            "timestamp": entry.timestamp.isoformat(),
            "event_type": entry.event_type,
            "actor": entry.actor,
            "system_name": entry.system_name,
            "details": entry.details,
        }
    
    async def get_last_hash(self, db: AsyncSession) -> str:
        """Get the hash of the last audit entry, or GENESIS if none exist."""
        result = await db.execute(
            select(AuditLog.hash)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        last_entry = result.scalar_one_or_none()
        
        if last_entry is None:
            # First entry - use genesis seed
            return self._compute_hash(self.GENESIS_HASH, {"seed": self.genesis_seed})
        
        return last_entry
    
    async def log(
        self,
        db: AsyncSession,
        event_type: str,
        actor: str,
        system_name: Optional[str] = None,
        details: Dict[str, Any] = None,
    ) -> AuditEntry:
        """
        Log an audit event with hash chain integrity.
        
        Args:
            db: Database session
            event_type: Type of event (e.g., "filter", "risk_score", "policy_check")
            actor: User or system that triggered the event
            system_name: Optional system name for filtering
            details: Additional event details
        
        Returns:
            The created AuditEntry
        """
        details = details or {}
        
        # Create entry
        entry = AuditEntry(
            timestamp=datetime.utcnow(),
            event_type=event_type,
            actor=actor,
            system_name=system_name,
            details=details,
        )
        
        # Get previous hash
        prev_hash = await self.get_last_hash(db)
        
        # Compute this entry's hash
        entry_data = self._prepare_entry_data(entry)
        entry.prev_hash = prev_hash
        entry.hash = self._compute_hash(prev_hash, entry_data)
        
        # Save to database
        db_entry = AuditLog(
            timestamp=entry.timestamp,
            event_type=entry.event_type,
            actor=entry.actor,
            system_name=entry.system_name,
            details=entry.details,
            hash=entry.hash,
            prev_hash=entry.prev_hash,
        )
        db.add(db_entry)
        await db.flush()
        
        entry.id = db_entry.id
        return entry
    
    async def get_trail(
        self,
        db: AsyncSession,
        system_name: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[AuditEntry], int]:
        """
        Retrieve audit trail with optional filters.
        
        Returns:
            Tuple of (entries, total_count)
        """
        # Build query
        query = select(AuditLog)
        count_query = select(func.count(AuditLog.id))
        
        # Apply filters
        if system_name:
            query = query.where(AuditLog.system_name == system_name)
            count_query = count_query.where(AuditLog.system_name == system_name)
        
        if event_type:
            query = query.where(AuditLog.event_type == event_type)
            count_query = count_query.where(AuditLog.event_type == event_type)
        
        if start_time:
            query = query.where(AuditLog.timestamp >= start_time)
            count_query = count_query.where(AuditLog.timestamp >= start_time)
        
        if end_time:
            query = query.where(AuditLog.timestamp <= end_time)
            count_query = count_query.where(AuditLog.timestamp <= end_time)
        
        # Get total count
        total_result = await db.execute(count_query)
        total = total_result.scalar_one()
        
        # Get entries with pagination
        query = query.order_by(AuditLog.id.desc()).offset(offset).limit(limit)
        result = await db.execute(query)
        db_entries = result.scalars().all()
        
        # Convert to AuditEntry objects
        entries = [
            AuditEntry(
                id=e.id,
                timestamp=e.timestamp,
                event_type=e.event_type,
                actor=e.actor,
                system_name=e.system_name,
                details=e.details,
                hash=e.hash,
                prev_hash=e.prev_hash,
            )
            for e in db_entries
        ]
        
        return entries, total
    
    async def verify_chain(
        self,
        db: AsyncSession,
        system_name: Optional[str] = None,
    ) -> VerificationResult:
        """
        Verify the integrity of the audit chain.
        
        Recomputes all hashes from genesis and compares to stored hashes.
        Any mismatch indicates tampering.
        
        Returns:
            VerificationResult with verification status and details
        """
        # Get all entries in order
        query = select(AuditLog).order_by(AuditLog.id.asc())
        if system_name:
            query = query.where(AuditLog.system_name == system_name)
        
        result = await db.execute(query)
        entries = result.scalars().all()
        
        if not entries:
            return VerificationResult(
                verified=True,
                total_entries=0,
                first_entry_hash="",
                last_entry_hash="",
                message="No audit entries to verify",
            )
        
        tampered_entries = []
        
        # Compute expected genesis hash
        expected_prev_hash = self._compute_hash(self.GENESIS_HASH, {"seed": self.genesis_seed})
        
        for entry in entries:
            # Prepare entry data
            entry_obj = AuditEntry(
                timestamp=entry.timestamp,
                event_type=entry.event_type,
                actor=entry.actor,
                system_name=entry.system_name,
                details=entry.details,
            )
            entry_data = self._prepare_entry_data(entry_obj)
            
            # Verify prev_hash matches expected
            if entry.prev_hash != expected_prev_hash:
                tampered_entries.append(entry.id)
            
            # Compute expected hash
            expected_hash = self._compute_hash(entry.prev_hash, entry_data)
            
            # Verify stored hash matches computed
            if entry.hash != expected_hash:
                tampered_entries.append(entry.id)
            
            # Update expected_prev_hash for next iteration
            expected_prev_hash = entry.hash
        
        verified = len(tampered_entries) == 0
        
        return VerificationResult(
            verified=verified,
            total_entries=len(entries),
            first_entry_hash=entries[0].hash,
            last_entry_hash=entries[-1].hash,
            message="Chain integrity verified" if verified else f"Tampering detected in {len(tampered_entries)} entries",
            tampered_entries=tampered_entries,
        )
    
    async def get_entry_by_hash(
        self,
        db: AsyncSession,
        hash: str,
    ) -> Optional[AuditEntry]:
        """Get a specific entry by its hash."""
        result = await db.execute(
            select(AuditLog).where(AuditLog.hash == hash)
        )
        entry = result.scalar_one_or_none()
        
        if entry is None:
            return None
        
        return AuditEntry(
            id=entry.id,
            timestamp=entry.timestamp,
            event_type=entry.event_type,
            actor=entry.actor,
            system_name=entry.system_name,
            details=entry.details,
            hash=entry.hash,
            prev_hash=entry.prev_hash,
        )


# Singleton instance
_audit_vault: Optional[AuditVault] = None


def get_audit_vault() -> AuditVault:
    """Get or create the audit vault singleton."""
    global _audit_vault
    if _audit_vault is None:
        _audit_vault = AuditVault()
    return _audit_vault
