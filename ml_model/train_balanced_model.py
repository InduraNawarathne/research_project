import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_curve, auc
from imblearn.over_sampling import SMOTE
import joblib

print("Step 1: Loading Dataset...")
df = pd.read_csv("dataset.csv")

# Clean any null values
df.dropna(inplace=True)
X_raw = df['api_sequence']
y = df['label']

print("\nStep 2: Extracting TF-IDF Features...")
# TF-IDF vectors turning text API sequences into numbers
vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=1000)
X = vectorizer.fit_transform(X_raw)

print(f"Original dataset shape: {y.value_counts().to_dict()}")

print("\nStep 3: Splitting the Data FIRST (Crucial to prevent Data Leakage)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ==========================================
# SUPER IMPORTANT CRITICAL ACADEMIC STEP
# ==========================================
print("\nStep 4: Balancing the dataset with SMOTE (fixing the 16% Benign recall)...")
print("Applying SMOTE ONLY to the training data to ensure the test set remains mathematically pure.")
smote = SMOTE(random_state=42)
X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)

print(f"Original training shape: {y_train.value_counts().to_dict()}")
print(f"Resampled training shape: {y_train_balanced.value_counts().to_dict()}")

print("\nStep 5: Training the Random Forest Classifier...")
# class_weight='balanced' helps even further, n_estimators=100 is standard
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
model.fit(X_train_balanced, y_train_balanced)

print("\nStep 6: Evaluating the Balanced Model...")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
print(classification_report(y_test, y_pred))

# ==========================================
# GENERATING ACADEMIC RESEARCH CHARTS
# ==========================================

print("Generating Confusion Matrix Chart...")
plt.figure(figsize=(6, 4))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Benign (0)', 'Malware (1)'], 
            yticklabels=['Benign (0)', 'Malware (1)'])
plt.title('Confusion Matrix (Balanced Data)')
plt.ylabel('Actual Label')
plt.xlabel('Predicted Label')
plt.tight_layout()
plt.savefig('confusion_matrix.png')
print("Saved 'confusion_matrix.png'")

print("Generating ROC-AUC Curve Chart...")
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)

plt.figure(figsize=(6, 4))
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate (FPR)')
plt.ylabel('True Positive Rate (TPR / Recall)')
plt.title('Receiver Operating Characteristic (ROC)')
plt.legend(loc="lower right")
plt.tight_layout()
plt.savefig('roc_curve.png')
print("Saved 'roc_curve.png'")

# ==========================================
print("\nStep 7: Saving the fully balanced models for integration...")
joblib.dump(model, "random_forest_model.pkl")
joblib.dump(vectorizer, "api_vectorizer.pkl")
print("Export complete. Models are theoretically balanced and ready for predict.py!")
