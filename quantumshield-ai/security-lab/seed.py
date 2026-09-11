"""
QuantumShield AI — Security Lab Database Seeder
Re-seeds the vulnerable SQLite database for testing and demonstration.
"""
import os
import sys

# Add security-lab to path if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import init_db, DB_PATH

if __name__ == "__main__":
    print(f"Initializing and seeding security lab database at: {DB_PATH}")
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            print(f"Removed existing database at {DB_PATH}")
        except Exception as e:
            print(f"Warning: could not remove existing DB: {e}")

    init_db()
    print("Security lab database successfully seeded with test accounts, orders, products, and vulnerable endpoints!")
