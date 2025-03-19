# Unsupervised Machine Learning Models

This directory contains unsupervised machine learning models trained on the CICIDS2017 dataset for network intrusion detection.

## Model Availability

Due to GitHub storage limitations, the actual model files are not included in this repository. However, all models are available and can be accessed through the following Kaggle notebook:

[CICIDS2017 ML Models Comparison - Unsupervised](https://www.kaggle.com/code/ericanacletoribeiro/cicids2017-ml-models-comparison-unsupervised)

## Available Models

The Kaggle notebook includes the training and evaluation of several unsupervised models:

- Isolation Forest
- K-Means Clustering

## Using the Models with the NIDS

After downloading the models from Kaggle:

1. Place the `.joblib` files in this directory
2. Ensure the corresponding scaler files are placed in the `../scalars/` directory
3. Run the appropriate NIDS prototype for your model:

```Python
prototype/nids_prototype_if.py # For Isolation Forest
prototype/nids_prototype_kmeans.py # For K-means
```

## Model Performance

The Kaggle notebook includes detailed performance metrics for each model, including:

- Accuracy
- Precision
- Recall
- F1-Score
- ROC curves
- Anomaly detection rates

For more information on how these models were trained and evaluated, please refer to the Kaggle notebook linked above.
