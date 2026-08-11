import pandas as pd
import joblib

from sklearn.model_selection import train_test_split

from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier
)

from sklearn.linear_model import LogisticRegression

from sklearn.tree import DecisionTreeClassifier

from sklearn.svm import SVC

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)

from feature_extraction import extract_features


# ============================================================
# SETTINGS
# ============================================================

DATASET_PATH = "dataset/urls.csv"

TEST_SIZE = 0.20

RANDOM_STATE = 42


# ============================================================
# LOAD DATASET
# ============================================================

print()
print("=" * 65)
print("             PHISHGUARD ML TRAINING ENGINE")
print("=" * 65)

print()
print("Loading dataset...")


data = pd.read_csv(
    DATASET_PATH
)


print(
    f"Dataset size: {len(data)} URLs"
)


# ============================================================
# CLEAN DATA
# ============================================================

data = data.dropna(
    subset=["url", "label"]
)


data["label"] = data["label"].astype(int)


# ============================================================
# FEATURE EXTRACTION
# ============================================================

print()
print("Extracting URL features...")


features = []

labels = []


for index, row in data.iterrows():

    try:

        feature_vector = extract_features(
            row["url"]
        )

        features.append(
            feature_vector
        )

        labels.append(
            row["label"]
        )

    except Exception as e:

        print(
            f"Skipping row {index}: {e}"
        )


X = features

y = labels


print(
    f"Features extracted: {len(X)}"
)


# ============================================================
# TRAIN TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = (
    train_test_split(

        X,
        y,

        test_size=TEST_SIZE,

        random_state=RANDOM_STATE,

        stratify=y

    )
)


print()
print(
    f"Training samples: {len(X_train)}"
)

print(
    f"Testing samples:  {len(X_test)}"
)


# ============================================================
# MODELS
# ============================================================

models = {

    "Random Forest":
        RandomForestClassifier(
            n_estimators=150,
            random_state=RANDOM_STATE,
            n_jobs=-1
        ),

    "Logistic Regression":
        LogisticRegression(
            max_iter=1000,
            random_state=RANDOM_STATE
        ),

    "Decision Tree":
        DecisionTreeClassifier(
            random_state=RANDOM_STATE
        ),

    "Gradient Boosting":
        GradientBoostingClassifier(
            random_state=RANDOM_STATE
        ),

    "SVM":
        SVC(
            probability=True,
            random_state=RANDOM_STATE
        )

}


# ============================================================
# TRAIN MODELS
# ============================================================

results = {}

trained_models = {}


for name, model in models.items():

    print()
    print("-" * 65)

    print(
        f"Training {name}..."
    )


    model.fit(
        X_train,
        y_train
    )


    predictions = model.predict(
        X_test
    )


    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )


    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )


    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )


    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )


    # --------------------------------------------------------
    # ROC AUC
    # --------------------------------------------------------

    try:

        probabilities = (
            model.predict_proba(
                X_test
            )[:, 1]
        )


        auc = roc_auc_score(
            y_test,
            probabilities
        )

    except Exception:

        auc = 0


    # --------------------------------------------------------
    # CONFUSION MATRIX
    # --------------------------------------------------------

    matrix = confusion_matrix(
        y_test,
        predictions
    )


    results[name] = {

        "accuracy":
            round(
                accuracy * 100,
                2
            ),

        "precision":
            round(
                precision * 100,
                2
            ),

        "recall":
            round(
                recall * 100,
                2
            ),

        "f1":
            round(
                f1 * 100,
                2
            ),

        "roc_auc":
            round(
                auc * 100,
                2
            ),

        "confusion_matrix":
            matrix.tolist()

    }


    trained_models[name] = model


    print(
        f"Accuracy:  {accuracy * 100:.2f}%"
    )

    print(
        f"Precision: {precision * 100:.2f}%"
    )

    print(
        f"Recall:    {recall * 100:.2f}%"
    )

    print(
        f"F1 Score:  {f1 * 100:.2f}%"
    )

    print(
        f"ROC-AUC:   {auc * 100:.2f}%"
    )


# ============================================================
# SELECT BEST MODEL
# ============================================================

best_model_name = max(

    results,

    key=lambda name:
        results[name]["f1"]

)


best_model = trained_models[
    best_model_name
]


print()
print("=" * 65)

print(
    f"BEST MODEL: {best_model_name}"
)

print("=" * 65)


# ============================================================
# SAVE BEST MODEL
# ============================================================

joblib.dump(

    best_model,

    "phishing_model.pkl"

)


print()
print(
    "✓ Best model saved as phishing_model.pkl"
)


# ============================================================
# SAVE ALL RESULTS
# ============================================================

joblib.dump(

    results,

    "model_results.pkl"

)


print(
    "✓ Model metrics saved as model_results.pkl"
)


# ============================================================
# FINAL TABLE
# ============================================================

print()
print("=" * 65)

print(
    "MODEL COMPARISON"
)

print("=" * 65)


print()

print(
    f"{'Model':<22}"
    f"{'Accuracy':<12}"
    f"{'Precision':<12}"
    f"{'Recall':<12}"
    f"{'F1':<12}"
)


print("-" * 65)


for name, metrics in results.items():

    print(

        f"{name:<22}"

        f"{metrics['accuracy']:<12}"

        f"{metrics['precision']:<12}"

        f"{metrics['recall']:<12}"

        f"{metrics['f1']:<12}"

    )


print()
print("=" * 65)
print("TRAINING COMPLETE")
print("=" * 65)