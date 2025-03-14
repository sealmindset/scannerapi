"""
Account Cache Module.

This module provides a centralized cache for storing and retrieving account credentials
that have been successfully created during scanning. This allows scanners to reuse
accounts rather than creating new ones for each test, improving efficiency and
reliability when dealing with APIs that have rate limiting or other restrictions.
"""

import json
import logging
import os
import time
from typing import Dict, List, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AccountCache:
    """A cache for storing and retrieving account credentials."""
    
    _instance = None
    
    def __new__(cls):
        """Implement singleton pattern to ensure only one cache exists."""
        if cls._instance is None:
            cls._instance = super(AccountCache, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize the account cache."""
        self.accounts = []
        self.cache_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'account_cache.json')
        self.last_used_index = -1
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        
        # Load existing accounts from cache file if it exists
        self._load_cache()
        
        logger.info(f"Account cache initialized with {len(self.accounts)} accounts")
    
    def _load_cache(self):
        """Load accounts from the cache file."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.accounts = json.load(f)
                logger.info(f"Loaded {len(self.accounts)} accounts from cache")
        except Exception as e:
            logger.error(f"Error loading account cache: {str(e)}")
            self.accounts = []
    
    def _save_cache(self):
        """Save accounts to the cache file."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.accounts, f, indent=2)
            logger.info(f"Saved {len(self.accounts)} accounts to cache")
        except Exception as e:
            logger.error(f"Error saving account cache: {str(e)}")
    
    def add_account(self, account: Dict[str, Any]) -> None:
        """
        Add an account to the cache.
        
        Args:
            account: A dictionary containing account credentials and metadata
        """
        # Add timestamp to track when the account was created
        account['created_at'] = time.time()
        account['last_used'] = time.time()
        
        # Check if account already exists (by username or email)
        for existing in self.accounts:
            if (existing.get('username') == account.get('username') or 
                existing.get('email') == account.get('email')):
                # Update existing account
                existing.update(account)
                logger.info(f"Updated existing account: {account.get('username', account.get('email'))}")
                self._save_cache()
                return
        
        # Add new account
        self.accounts.append(account)
        logger.info(f"Added new account to cache: {account.get('username', account.get('email'))}")
        self._save_cache()
    
    def get_account(self, endpoint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get an account from the cache, preferring accounts that were created for the given endpoint.
        
        Args:
            endpoint: Optional endpoint for which the account was created
            
        Returns:
            An account dictionary or None if no accounts are available
        """
        if not self.accounts:
            logger.warning("No accounts available in cache")
            return None
        
        # First try to find an account created for this specific endpoint
        if endpoint:
            endpoint_accounts = [a for a in self.accounts if a.get('endpoint') == endpoint]
            if endpoint_accounts:
                # Use round-robin to avoid using the same account repeatedly
                self.last_used_index = (self.last_used_index + 1) % len(endpoint_accounts)
                account = endpoint_accounts[self.last_used_index]
                account['last_used'] = time.time()
                logger.info(f"Using cached account for endpoint {endpoint}: {account.get('username', account.get('email'))}")
                self._save_cache()
                return account
        
        # If no endpoint-specific account is found, use any account
        self.last_used_index = (self.last_used_index + 1) % len(self.accounts)
        account = self.accounts[self.last_used_index]
        account['last_used'] = time.time()
        logger.info(f"Using cached account: {account.get('username', account.get('email'))}")
        self._save_cache()
        return account
    
    def get_all_accounts(self) -> List[Dict[str, Any]]:
        """
        Get all accounts from the cache.
        
        Returns:
            A list of all account dictionaries
        """
        return self.accounts
    
    def clear_cache(self) -> None:
        """Clear all accounts from the cache."""
        self.accounts = []
        self._save_cache()
        logger.info("Account cache cleared")
    
    def remove_account(self, identifier: str) -> bool:
        """
        Remove an account from the cache by username or email.
        
        Args:
            identifier: Username or email of the account to remove
            
        Returns:
            True if the account was removed, False otherwise
        """
        initial_count = len(self.accounts)
        self.accounts = [a for a in self.accounts if 
                         a.get('username') != identifier and 
                         a.get('email') != identifier]
        
        if len(self.accounts) < initial_count:
            logger.info(f"Removed account {identifier} from cache")
            self._save_cache()
            return True
        
        logger.warning(f"Account {identifier} not found in cache")
        return False

# Create a singleton instance
account_cache = AccountCache()
