import json
import os
from typing import Any, Dict, List


def save_json(data: Any, filepath: str) -> bool:
    """Save data to JSON file"""
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"❌ Error saving JSON: {e}")
        return False


def load_json(filepath: str) -> Dict:
    """Load data from JSON file"""
    try:
        if not os.path.exists(filepath):
            print(f"❌ File not found: {filepath}")
            return {}
        
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading JSON: {e}")
        return {}


def print_banner(text: str):
    """Print centered banner"""
    print("\n" + "="*60)
    print(text.center(60))
    print("="*60 + "\n")


def print_success(text: str):
    """Print success message"""
    print(f"✅ {text}")


def print_error(text: str):
    """Print error message"""
    print(f"❌ {text}")


def print_info(text: str):
    """Print info message"""
    print(f"ℹ️  {text}")


def print_warning(text: str):
    """Print warning message"""
    print(f"⚠️  {text}")