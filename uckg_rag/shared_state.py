import json
import os
import threading
from datetime import datetime
from typing import Set, Dict, Any

# Singleton class to track embedding progress across threads
class SharedState:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(SharedState, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self.processed_uris: Set[str] = set()
            self.total_records: int = 0
            self.processed_count: int = 0
            self.is_embedding_complete: bool = False
            self.last_update: datetime = datetime.now()
            self._load_state()
    
    def _load_state(self):
        """Load state from checkpoint.json"""
        checkpoint_path = os.path.join('checkpoints', 'checkpoint.json')
        if os.path.exists(checkpoint_path):
            try:
                with open(checkpoint_path, 'r') as f:
                    data = json.load(f)
                    self.processed_uris = set(data.get('processed_uris', []))
                    self.total_records = data.get('total_records', 0)
                    self.processed_count = data.get('processed_count', 0)
                    self.is_embedding_complete = data.get('is_embedding_complete', False)
                    self.last_update = datetime.fromisoformat(data.get('last_update', datetime.now().isoformat()))
            except Exception as e:
                print(f"Error loading checkpoint: {e}")
    
    def _save_state(self):
        """Save state to checkpoint.json"""
        checkpoint_path = os.path.join('checkpoints', 'checkpoint.json')
        os.makedirs(os.path.dirname(checkpoint_path), exist_ok=True)
        try:
            with open(checkpoint_path, 'w') as f:
                json.dump({
                    'processed_uris': list(self.processed_uris),
                    'total_records': self.total_records,
                    'processed_count': self.processed_count,
                    'is_embedding_complete': self.is_embedding_complete,
                    'last_update': self.last_update.isoformat()
                }, f)
        except Exception as e:
            print(f"Error saving checkpoint: {e}")
    
    def reset(self):
        """Reset the shared state"""
        with self._lock:
            self.processed_uris.clear()
            self.total_records = 0
            self.processed_count = 0
            self.is_embedding_complete = False
            self.last_update = datetime.now()
            self._save_state()
    
    def update_progress(self, processed_uris: Set[str], total_records: int, processed_count: int):
        """Update the embedding progress"""
        with self._lock:
            self.processed_uris.update(processed_uris)
            self.total_records = total_records
            self.processed_count = processed_count
            self.last_update = datetime.now()
            self._save_state()
    
    def get_progress(self) -> Dict[str, Any]:
        """Get the current embedding progress"""
        with self._lock:
            return {
                'processed_count': self.processed_count,
                'total_records': self.total_records,
                'is_complete': self.is_embedding_complete,
                'last_update': self.last_update.isoformat(),
                'progress_percentage': (self.processed_count / self.total_records * 100) if self.total_records > 0 else 0
            }
    
    def is_uri_processed(self, uri: str) -> bool:
        """Check if a URI has been processed"""
        with self._lock:
            return uri in self.processed_uris
    
    def get_processed_uris(self) -> Set[str]:
        """Get the set of processed URIs"""
        with self._lock:
            return self.processed_uris.copy()