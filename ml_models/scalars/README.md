# Scalers for Machine Learning Models

This directory contains pre-saved scaler objects (e.g., `RobustScaler`) used during the training of the machine learning models in this project. These scalers were fitted on the specific training data split used in the original experiments.

## ⚠️ Important Notice for Replication

**If you are attempting to replicate this project, retrain the models, or run the feature extraction and prediction pipeline with your own data or a different split of the CICIDS2017 dataset, it is CRUCIAL that you:**

1.  **DO NOT directly use the scaler file(s) provided in this directory for your own training or prediction pipeline.**
2.  **ALWAYS fit a NEW scaler object on YOUR specific training dataset.**
3.  **Save and use YOUR OWN fitted scaler for transforming both your training data and any new data you intend to make predictions on (e.g., test data, live traffic features).**

### Why is this important?

- **Data Distribution:** Scalers (like `StandardScaler`, `MinMaxScaler`, `RobustScaler`) learn parameters (e.g., mean, standard deviation, quantiles) from the data they are `fit` on. If you use a scaler fitted on a different dataset (or even a different random split of the same dataset), these learned parameters will not be appropriate for your data, leading to incorrect scaling.
- **Data Leakage:** Using a scaler fitted on data that includes your test set or future unseen data constitutes data leakage, which can lead to overly optimistic performance metrics and poor generalization to new, truly unseen data.
- **Reproducibility and Correctness:** For accurate and reproducible results, the scaling process must be treated as part of the model training pipeline and be specific to the training data fold being used.

### How to proceed:

When running the data processing and model training notebooks (e.g., `cicids2017-ml-models-comparison-supervised.ipynb`):

1.  Ensure the notebook code includes steps to initialize a new scaler object.
2.  Fit this new scaler object **only on the training portion** of your data.
    ```python
    # Example (conceptual)
    from sklearn.preprocessing import RobustScaler
    # ... load and split your data into X_train, X_test ...
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test) # Use the SAME fitted scaler
    # ... save your 'scaler' object using joblib ...
    ```
3.  Save this newly fitted scaler object.
4.  Use this saved scaler in your NIDS prototype to transform incoming network traffic features before feeding them to the model.

By following this practice, you ensure that the feature scaling is performed correctly and is consistent with the model training process.
