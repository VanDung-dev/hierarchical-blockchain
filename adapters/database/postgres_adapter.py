"""
PostgreSQL adapter for Hierarchical Blockchain Framework

This module provides a PostgreSQL database adapter for the Hierarchical Blockchain Framework. 
It implements storage and retrieval operations for blockchain data including chains, blocks, and events.
"""

import json
import logging
from typing import List, Dict
from datetime import datetime
from contextlib import contextmanager

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

logger = logging.getLogger(__name__)

class PostgresAdapter:
    """PostgreSQL database adapter for blockchain data storage"""
    
    def __init__(self, connection_string: str):
        """
        Initialize PostgreSQL adapter
        
        Args:
            connection_string: PostgreSQL connection string
                Format: "postgresql://user:password@host:port/database"
        """
        if not POSTGRES_AVAILABLE:
            raise ImportError("psycopg2 is required for PostgreSQL adapter. Install with: pip install psycopg2-binary")
        
        self.connection_string = connection_string
        self.connection = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Establish connection to PostgreSQL database"""
        try:
            self.connection = psycopg2.connect(
                self.connection_string,
                cursor_factory=RealDictCursor
            )
            self.connection.autocommit = True
            logger.info("Connected to PostgreSQL database")
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise
    
    def _create_tables(self):
        """Create necessary tables for blockchain data"""
        with self._get_cursor() as cursor:
            try:
                # Chains table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS chains (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255) UNIQUE NOT NULL,
                        type VARCHAR(50) NOT NULL,
                        parent_chain VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        metadata JSONB
                    )
                """)
                
                # Blocks table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS blocks (
                        id SERIAL PRIMARY KEY,
                        chain_name VARCHAR(255) NOT NULL,
                        block_index INTEGER NOT NULL,
                        hash VARCHAR(64) NOT NULL,
                        previous_hash VARCHAR(64),
                        timestamp TIMESTAMP NOT NULL,
                        nonce INTEGER DEFAULT 0,
                        events JSONB NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(chain_name, block_index),
                        FOREIGN KEY (chain_name) REFERENCES chains(name)
                    )
                """)
                
                # Events table (for faster querying)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id SERIAL PRIMARY KEY,
                        chain_name VARCHAR(255) NOT NULL,
                        block_index INTEGER NOT NULL,
                        entity_id VARCHAR(255),
                        event_type VARCHAR(100) NOT NULL,
                        timestamp TIMESTAMP NOT NULL,
                        details JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (chain_name) REFERENCES chains(name)
                    )
                """)
                
                # Create indexes for better performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocks_chain_name ON blocks(chain_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_entity_id ON events(entity_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_chain_name ON events(chain_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
                
                logger.info("PostgreSQL tables created successfully")
                
            except Exception as e:
                logger.error(f"Failed to create tables: {e}")
                raise
    
    @contextmanager
    def _get_cursor(self):
        """Context manager for database cursors"""
        cursor = self.connection.cursor()
        try:
            yield cursor
        finally:
            cursor.close()
    
    def _execute_query(self, query, params=None):
        """Execute a query and return the result"""
        with self._get_cursor() as cursor:
            cursor.execute(query, params or [])
            return cursor.fetchone()
    
    def _execute_query_all(self, query, params=None):
        """Execute a query and return all results"""
        with self._get_cursor() as cursor:
            cursor.execute(query, params or [])
            return cursor.fetchall()
    
    @staticmethod
    def _build_dict_from_row(row, field_mapping):
        """Build dictionary from database row using field mapping"""
        result = {}
        for key, value in field_mapping.items():
            if callable(value):
                result[key] = value(row)
            else:
                result[key] = row.get(value)
        return result
    
    @staticmethod
    def _build_chain_stats_dict(chain_name, row):
        """Build chain statistics dictionary from query result"""
        field_mapping = {
            'chain_name': lambda r: chain_name,
            'total_blocks': 'total_blocks',
            'unique_entities': 'unique_entities',
            'total_events': 'total_events',
            'first_event': lambda r: r['first_event'].timestamp() if r['first_event'] else None,
            'last_event': lambda r: r['last_event'].timestamp() if r['last_event'] else None
        }
        return PostgresAdapter._build_dict_from_row(row, field_mapping)
    
    def store_chain(self, chain_name: str, chain_type: str, parent_chain: str = None, metadata: Dict = None):
        """Store chain information"""
        with self._get_cursor() as cursor:
            try:
                cursor.execute("""
                    INSERT INTO chains (name, type, parent_chain, metadata)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (name) DO UPDATE SET
                        type = EXCLUDED.type,
                        parent_chain = EXCLUDED.parent_chain,
                        metadata = EXCLUDED.metadata
                """, (chain_name, chain_type, parent_chain, json.dumps(metadata or {})))
                
                logger.debug(f"Stored chain: {chain_name}")
                
            except Exception as e:
                logger.error(f"Failed to store chain {chain_name}: {e}")
                raise
    
    def store_block(self, chain_name: str, block_data: Dict):
        """Store block data"""
        with self._get_cursor() as cursor:
            try:
                # Store block
                cursor.execute("""
                    INSERT INTO blocks (chain_name, block_index, hash, previous_hash, timestamp, nonce, events)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (chain_name, block_index) DO UPDATE SET
                        hash = EXCLUDED.hash,
                        previous_hash = EXCLUDED.previous_hash,
                        timestamp = EXCLUDED.timestamp,
                        nonce = EXCLUDED.nonce,
                        events = EXCLUDED.events
                """, (
                    chain_name,
                    block_data['index'],
                    block_data['hash'],
                    block_data['previous_hash'],
                    datetime.fromtimestamp(block_data['timestamp']),
                    block_data.get('nonce', 0),
                    json.dumps(block_data['events'])
                ))
                
                # Store individual events for faster querying
                for event in block_data['events']:
                    cursor.execute("""
                        INSERT INTO events (chain_name, block_index, entity_id, event_type, timestamp, details)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        chain_name,
                        block_data['index'],
                        event.get('entity_id'),
                        event.get('event', event.get('event_type')),
                        datetime.fromtimestamp(event.get('timestamp', block_data['timestamp'])),
                        json.dumps(event.get('details', {}))
                    ))
                
                logger.debug(f"Stored block {block_data['index']} for chain {chain_name}")
                
            except Exception as e:
                logger.error(f"Failed to store block: {e}")
                raise
    
    def get_chain_blocks(self, chain_name: str, limit: int = None, offset: int = 0) -> List[Dict]:
        """Get blocks for a specific chain"""
        with self._get_cursor() as cursor:
            try:
                query = """
                    SELECT block_index, hash, previous_hash, timestamp, nonce, events
                    FROM blocks
                    WHERE chain_name = %s
                    ORDER BY block_index
                """
                params = [chain_name]
                
                if limit:
                    query += " LIMIT %s OFFSET %s"
                    params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                blocks = []
                for row in rows:
                    blocks.append({
                        'index': row['block_index'],
                        'hash': row['hash'],
                        'previous_hash': row['previous_hash'],
                        'timestamp': row['timestamp'].timestamp(),
                        'nonce': row['nonce'],
                        'events': row['events']
                    })
                
                return blocks
                
            except Exception as e:
                logger.error(f"Failed to get blocks for chain {chain_name}: {e}")
                raise
    
    def get_entity_events(self, entity_id: str, chain_name: str = None) -> List[Dict]:
        """Get all events for a specific entity"""
        with self._get_cursor() as cursor:
            try:
                query = """
                    SELECT chain_name, block_index, event_type, timestamp, details
                    FROM events
                    WHERE entity_id = %s
                """
                params = [entity_id]
                
                if chain_name:
                    query += " AND chain_name = %s"
                    params.append(chain_name)
                
                query += " ORDER BY timestamp"
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                events = []
                for row in rows:
                    events.append({
                        'chain_name': row['chain_name'],
                        'block_index': row['block_index'],
                        'event_type': row['event_type'],
                        'timestamp': row['timestamp'].timestamp(),
                        'details': row['details']
                    })
                
                return events
                
            except Exception as e:
                logger.error(f"Failed to get events for entity {entity_id}: {e}")
                raise
    
    def get_chain_stats(self, chain_name: str) -> Dict:
        """Get statistics for a specific chain"""
        try:
            row = self._execute_query("""
                SELECT 
                    COUNT(DISTINCT b.block_index) as total_blocks,
                    COUNT(DISTINCT e.entity_id) as unique_entities,
                    COUNT(e.entity_id) as total_events,
                    MIN(e.timestamp) as first_event,
                    MAX(e.timestamp) as last_event
                FROM blocks b
                LEFT JOIN events e ON b.chain_name = e.chain_name AND b.block_index = e.block_index
                WHERE b.chain_name = %s
            """, (chain_name,))
            
            return self._build_chain_stats_dict(chain_name, row)
        except Exception as e:
            logger.error(f"Failed to get stats for chain {chain_name}: {e}")
            raise
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("PostgreSQL connection closed")