"""
Pydantic schemas for API requests and responses

This module defines the data models used for validating and serializing
API requests and responses in the hierarchical blockchain system.
Each schema corresponds to specific API endpoints and ensures data integrity
and proper documentation.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class EventRequest(BaseModel):
    """Request schema for adding events"""
    entity_id: str = Field(..., description="Unique identifier for the entity")
    event_type: str = Field(..., description="Type of event (e.g., 'operation_start', 'status_change')")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional event details")
    
    class Config:
        schema_extra = {
            "example": {
                "entity_id": "PRODUCT-2024-001",
                "event_type": "production_start",
                "details": {
                    "material_batch": "BATCH-001",
                    "machine_id": "MACHINE-07"
                }
            }
        }

class EventResponse(BaseModel):
    """Response schema for event operations"""
    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Response message")
    event_id: Optional[str] = Field(None, description="Generated event ID")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "message": "Event added to chain 'production_chain'",
                "event_id": "production_chain_1_5"
            }
        }

class ChainInfoResponse(BaseModel):
    """Response schema for chain information"""
    name: str = Field(..., description="Chain name")
    type: str = Field(..., description="Chain type (main or sub)")
    block_count: int = Field(..., description="Number of blocks in the chain")
    latest_block_hash: Optional[str] = Field(None, description="Hash of the latest block")
    parent_chain: Optional[str] = Field(None, description="Parent chain name")
    
    class Config:
        schema_extra = {
            "example": {
                "name": "production_chain",
                "type": "sub",
                "block_count": 15,
                "latest_block_hash": "abc123def456...",
                "parent_chain": "main_chain"
            }
        }

class ProofSubmissionRequest(BaseModel):
    """Request schema for proof submission"""
    metadata: Optional[Dict[str, Any]] = Field(None, description="Custom metadata for the proof")
    
    class Config:
        schema_extra = {
            "example": {
                "metadata": {
                    "domain_type": "Manufacturing",
                    "completed_operations": 25,
                    "quality_checks_passed": 23
                }
            }
        }

class ProofSubmissionResponse(BaseModel):
    """Response schema for proof submission"""
    success: bool = Field(..., description="Whether the proof submission was successful")
    message: str = Field(..., description="Response message")
    proof_hash: Optional[str] = Field(None, description="Hash of the submitted proof")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "message": "Proof submitted from 'production_chain' to main chain",
                "proof_hash": "def789abc123..."
            }
        }

class EntityEvent(BaseModel):
    """Schema for entity events in trace responses"""
    chain_name: str = Field(..., description="Name of the chain containing the event")
    block_index: int = Field(..., description="Index of the block containing the event")
    event_type: str = Field(..., description="Type of the event")
    timestamp: float = Field(..., description="Event timestamp")
    details: Dict[str, Any] = Field(..., description="Event details")
    
    class Config:
        schema_extra = {
            "example": {
                "chain_name": "production_chain",
                "block_index": 5,
                "event_type": "quality_check",
                "timestamp": 1717987200.0,
                "details": {
                    "result": "pass",
                    "inspector_id": "INSPECTOR-03"
                }
            }
        }

class EntityTraceResponse(BaseModel):
    """Response schema for entity tracing"""
    entity_id: str = Field(..., description="Entity ID that was traced")
    events: List[EntityEvent] = Field(..., description="List of events for the entity")
    total_events: int = Field(..., description="Total number of events found")
    
    class Config:
        schema_extra = {
            "example": {
                "entity_id": "PRODUCT-2024-001",
                "events": [
                    {
                        "chain_name": "production_chain",
                        "block_index": 3,
                        "event_type": "production_start",
                        "timestamp": 1717987000.0,
                        "details": {"material_batch": "BATCH-001"}
                    }
                ],
                "total_events": 1
            }
        }

class ChainStatsResponse(BaseModel):
    """Response schema for chain statistics"""
    chain_name: str = Field(..., description="Name of the chain")
    total_blocks: int = Field(..., description="Total number of blocks")
    total_events: int = Field(..., description="Total number of events")
    unique_entities: int = Field(..., description="Number of unique entities")
    latest_block_hash: Optional[str] = Field(None, description="Hash of the latest block")
    created_at: float = Field(..., description="Chain creation timestamp")
    
    class Config:
        schema_extra = {
            "example": {
                "chain_name": "production_chain",
                "total_blocks": 15,
                "total_events": 87,
                "unique_entities": 23,
                "latest_block_hash": "abc123def456...",
                "created_at": 1717900000.0
            }
        }

class BlockInfo(BaseModel):
    """Schema for block information"""
    index: int = Field(..., description="Block index")
    hash: str = Field(..., description="Block hash")
    previous_hash: str = Field(..., description="Previous block hash")
    timestamp: float = Field(..., description="Block timestamp")
    events_count: int = Field(..., description="Number of events in the block")
    events: List[Dict[str, Any]] = Field(..., description="Events in the block")
    
    class Config:
        schema_extra = {
            "example": {
                "index": 5,
                "hash": "abc123def456...",
                "previous_hash": "def456abc789...",
                "timestamp": 1717987200.0,
                "events_count": 3,
                "events": [
                    {
                        "entity_id": "PRODUCT-001",
                        "event": "quality_check",
                        "timestamp": 1717987200.0,
                        "details": {"result": "pass"}
                    }
                ]
            }
        }

class ChainBlocksResponse(BaseModel):
    """Response schema for chain blocks"""
    chain_name: str = Field(..., description="Name of the chain")
    blocks: List[BlockInfo] = Field(..., description="List of blocks")
    total_blocks: int = Field(..., description="Total number of blocks in the chain")
    offset: int = Field(..., description="Offset used for pagination")
    limit: int = Field(..., description="Limit used for pagination")
    
    class Config:
        schema_extra = {
            "example": {
                "chain_name": "production_chain",
                "blocks": [],
                "total_blocks": 15,
                "offset": 0,
                "limit": 10
            }
        }

class CreateChainRequest(BaseModel):
    """Request schema for creating a new chain"""
    chain_type: str = Field(default="generic", description="Type of chain to create")
    participants: Optional[List[str]] = Field(None, description="List of participants")
    
    class Config:
        schema_extra = {
            "example": {
                "chain_type": "supply_chain",
                "participants": ["manufacturer", "supplier", "distributor"]
            }
        }

class CreateChainResponse(BaseModel):
    """Response schema for chain creation"""
    success: bool = Field(..., description="Whether the chain creation was successful")
    message: str = Field(..., description="Response message")
    chain_name: str = Field(..., description="Name of the created chain")
    chain_type: str = Field(..., description="Type of the created chain")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "message": "Sub-chain 'production_chain' created successfully",
                "chain_name": "production_chain",
                "chain_type": "generic"
            }
        }

class HealthResponse(BaseModel):
    """Response schema for health check"""
    status: str = Field(..., description="Health status")
    timestamp: float = Field(..., description="Current timestamp")
    
    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": 1717987200.0
            }
        }