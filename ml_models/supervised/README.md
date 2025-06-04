# Supervised Machine Learning Models

This directory contains supervised machine learning models trained on the CICIDS2017 dataset for network intrusion detection.

## Model Availability

Due to GitHub storage limitations, the actual model files are not included in this repository. However, all models are available and can be accessed through the following Kaggle notebook:

[CICIDS2017 ML Models Comparison - Supervised](https://www.kaggle.com/code/ericanacletoribeiro/cicids2017-ml-models-comparison-supervised)

## Available Models

The Kaggle notebook includes the training and evaluation of several supervised models:

- Random Forest
- XGBoost
- KNN (K-Nearest Neighbors)

## Using the Models with the NIDS

After downloading the models from Kaggle:

1. Place the `.joblib` files in this directory
2. Ensure the corresponding scaler files are placed in the `../scalars/` directory
3. Run the appropriate NIDS prototype for your model:

```Python
prototype/nids_prototype_xgboost.py # For XGBoost
prototype/nids_prototype_knn.py # For KNN
```

You will need to adapt the code from e.g. nids_prototype_xgboost in order to run other models (like RF). Considering the performance results, I did not develop individual scripts for each model.

## Model Performance

The Kaggle notebook includes detailed performance metrics for each model, including:

- Accuracy
- Precision
- Recall
- F1-Score
- Confusion matrices

For more information on how these models were trained and evaluated, please refer to the Kaggle notebook linked above.
