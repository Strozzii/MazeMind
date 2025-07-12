"""
A one-off script to train a dummy machine learning model.

This script generates a synthetic dataset, trains a Logistic Regression model on it,
and saves the trained model to a file for the application to use. This is necessary
because we don't have real-world labeled data for training.
"""
import joblib
import numpy as np
from pathlib import Path
from sklearn.linear_model import LogisticRegression

# --- Configuration ---
NUM_FEATURES = 7
NUM_SAMPLES = 200

# --- Path Definition (The Fix) ---
# Build a robust path to the project root directory
# __file__ is the path to this script (model_training.py)
# .parent.parent.parent goes up three levels (ariadne -> src -> project root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Define the model path relative to the project root
MODEL_DIR = PROJECT_ROOT / "data" / "models"
MODEL_NAME = "ariadne_model.joblib"
MODEL_PATH = MODEL_DIR / MODEL_NAME


def train_and_save_dummy_model():
    """
    Generates dummy data, trains a model, and saves it to disk.
    """
    print("--- Starting Dummy Model Training ---")

    # 1. Generate Dummy Data
    print(f"Generating {NUM_SAMPLES} samples with {NUM_FEATURES} features...")
    X = np.random.rand(NUM_SAMPLES, NUM_FEATURES) * 10
    y = np.random.randint(0, 2, size=NUM_SAMPLES)

    # 2. Train the Model
    print("Training Logistic Regression model...")
    model = LogisticRegression()
    model.fit(X, y)
    print("Model training complete.")

    # 3. Save the Model
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(model, MODEL_PATH)
    print("✅ Model saved successfully.")
    print("-------------------------------------")


if __name__ == "__main__":
    train_and_save_dummy_model()