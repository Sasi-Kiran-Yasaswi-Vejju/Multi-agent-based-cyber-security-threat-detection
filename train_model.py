"""
Root launcher for model training script.
Allows running:
  python train_model.py
"""

import os
import sys

PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersecurity_multi_agent")
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from train_model import prepare_and_train

if __name__ == "__main__":
    prepare_and_train()
