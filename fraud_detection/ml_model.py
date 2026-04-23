import numpy as np, os, joblib
from sklearn.linear_model import LogisticRegression

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'fraud_model.joblib')

BILL_MAP = {
    "Electricity": 0, "Water": 1, "Mobile": 2, "Internet": 3,
    "Transfer": 4, "External Transfer": 5, "Admin Adjustment": 6,
}


def train_model():
    np.random.seed(42)
    n_n = 300
    X_n = np.column_stack([np.random.uniform(100, 8000, n_n), np.random.randint(0, 7, n_n)])
    y_n = np.zeros(n_n)
    n_f = 100
    X_f = np.column_stack([np.random.uniform(15000, 100000, n_f), np.random.randint(0, 7, n_f)])
    y_f = np.ones(n_f)
    n_e = 60
    ae  = np.random.uniform(8000, 15000, n_e)
    X_e = np.column_stack([ae, np.random.randint(0, 7, n_e)])
    y_e = np.where(ae > 12000, 1, 0)
    X   = np.vstack([X_n, X_f, X_e])
    y   = np.concatenate([y_n, y_f, y_e])
    m   = LogisticRegression(max_iter=500)
    m.fit(X, y)
    joblib.dump(m, MODEL_PATH)
    return m


_model = None


def get_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else train_model()
    return _model


def predict_fraud(amount, bill_type):
    code = BILL_MAP.get(bill_type, 0)
    return get_model().predict([[float(amount), code]])[0]


def get_risk_level(score):
    if score < 40:  return 'LOW'
    if score < 70:  return 'MEDIUM'
    return 'HIGH'
