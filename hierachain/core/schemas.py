"""
Arrow Schemas for HieraChain Core Data Structures.

This module defines the Apache Arrow schemas used for:
- Events: Domain-specific actions
- Blocks: Groups of events
- BlockHeaders: Metadata for blocks
"""

import pyarrow as pa

# Event Schema - Simple structure for events
EVENT_SCHEMA = pa.schema([
    ('entity_id', pa.string()),
    ('event', pa.string()),
    ('timestamp', pa.float64()),
    ('details', pa.map_(pa.string(), pa.string())),
    ('data', pa.binary()),
])


# Block Header Schema
BLOCK_HEADER_SCHEMA = pa.schema([
    ('index', pa.int64()),
    ('timestamp', pa.float64()),
    ('previous_hash', pa.string()),
    ('nonce', pa.int64()),
    ('merkle_root', pa.string()),
    ('hash', pa.string()),
])


def get_event_schema() -> pa.Schema:
    """Return the Arrow schema for an Event."""
    return EVENT_SCHEMA


def get_block_header_schema() -> pa.Schema:
    """Return the Arrow schema for a Block Header."""
    return BLOCK_HEADER_SCHEMA


def get_block_schema() -> pa.Schema:
    """Return the Arrow schema for a full Block (header + events)."""
    return pa.schema([
        ('index', pa.int64()),
        ('timestamp', pa.float64()),
        ('previous_hash', pa.string()),
        ('nonce', pa.int64()),
        ('merkle_root', pa.string()),
        ('hash', pa.string()),
        ('events', pa.list_(pa.struct([
            ('entity_id', pa.string()),
            ('event', pa.string()),
            ('timestamp', pa.float64()),
            ('details', pa.map_(pa.string(), pa.string())),
            ('data', pa.binary()),
        ]))),
    ])

# Constants for conversion
SERIALIZATION_METADATA_KEY = b'hiera_metadata'
