import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from feature_extraction import extract_features


# Load dataset
data = pd.read_csv("dataset/urls.csv")


# Extract URL features
X = data["url"].apply(extract_features).tolist()

y = data["label"]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# Random Forest model
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)


# Train
model.fit(X_train, y_train)


# Test
predictions = model.predict(X_test)


accuracy = accuracy_score(
    y_test,
    predictions
)


print("Model Accuracy:", accuracy)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions
    )
)


# Save model
joblib.dump(
    model,
    "phishing_model.pkl"
)


print("\nModel saved as phishing_model.pkl")