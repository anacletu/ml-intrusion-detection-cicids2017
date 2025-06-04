# NIDS Prototype Implementations

This directory contains the Python scripts for the Network Intrusion Detection System (NIDS) prototypes developed as part of the "Anomaly-based intrusion detection in resource-limited networks" project.

## Available Prototypes

- **`nids__prototype_knn.py`**: This is the primary NIDS prototype utilizing a K-Nearest Neighbors (KNN) model. This version demonstrated the most promising adaptability and practical performance during validation with replayed network traffic (`pcap` files) on a resource-constrained device (Raspberry Pi 5). It includes a Tkinter-based GUI for real-time monitoring and alert management.
- **`nids_prototype_xgboost.py`**: An exploratory NIDS prototype based on the XGBoost model. While XGBoost showed high accuracy on the static CICIDS2017 dataset during training, this prototype was less robust in simulated real-world traffic tests compared to the KNN version.

## Adapting the Prototype for Other Trained Models

Due to the performance results observed during the model evaluation phase (detailed in the thesis) and project time constraints, prototypes were not individually coded for every machine learning model trained (e.g., Random Forest, Isolation Forest, K-Means).

However, the existing `nids__prototype_knn.py` (or `nids_prototype_xgboost.py`) script can serve as a solid template for integrating other models you might have trained using the notebooks in the root directory. The core logic for packet sniffing (`scapy`), flow creation, feature extraction, and the GUI is largely reusable.

If you wish to adapt the prototype for a different model, here are key areas in the `nids__prototype_knn.py` (or `nids_prototype_xgboost.py`) script you'll likely need to modify:

1.  **Model and Scaler Paths (Constants):**

    - Update the `MODEL_PATH` and `SCALAR_PATH` constants at the beginning of the script to point to your new model file and its corresponding scaler (if applicable).
      ```python
      # Example for a Random Forest model
      MODEL_PATH = os.path.join(nids_script_dir,'../ml_models/supervised/random_forest_model.joblib')
      SCALAR_PATH = os.path.join(nids_script_dir,'../ml_models/scalars/robust_scalar_supervised.joblib') # Or your RF-specific scaler
      ```

2.  **Model Loading (in `NetworkAnomalyDetector.__init__`):**

    - The model is loaded using `joblib.load()`. This part should remain similar, just ensure the path is correct.
      ```python
      with open(self.model_path, 'rb') as f: # self.model_path would use MODEL_PATH
          self.model = joblib.load(f)
      # If your new model doesn't use a separate scaler file, you might remove/adjust scaler loading
      with open(SCALAR_PATH, 'rb') as f:
          self.rb_scalar = joblib.load(f)
      ```

3.  **Feature Scaling (in `NetworkAnomalyDetector.detect_anomalies`):**

    - The current prototype applies a `RobustScaler`. If your new model was trained with a different scaler, or no scaler, you'll need to adjust this part.
      ```python
      # df = self.rb_scalar.transform(df) # Modify or remove if necessary
      ```
    - Ensure the features (`df`) being passed to the model are scaled _exactly_ as they were during the training of the new model.

4.  **Required Features (in `NetworkAnomalyDetector.detect_anomalies`):**

    - The `required_features` list ensures the DataFrame has the correct columns in the correct order before prediction. This list **must match the feature set and order used to train your new model.**
      ```python
      required_features = [
          'Destination Port', 'Flow Duration', ... # Update this list if your new model used a different feature set/order
      ]
      df = df.reindex(columns=required_features, fill_value=0)
      ```

5.  **Prediction and Alert Logic (in `NetworkAnomalyDetector.detect_anomalies`):**

    - **Supervised Models (e.g., Random Forest, other classifiers):**
      The prediction line `predicted_class = self.model.predict(df)[0]` will likely be similar. The condition `if predicted_class != 'Normal Traffic':` should also work if your model outputs class labels including "Normal Traffic".
    - **Unsupervised Models (e.g., Isolation Forest, K-Means):**
      The output and interpretation will differ:
      - **Isolation Forest:** Typically outputs `-1` for anomalies and `1` for inliers.
        ```python
        # Example for Isolation Forest
        prediction_score = self.model.predict(df)[0]
        if prediction_score == -1: # Assuming -1 indicates an anomaly
            predicted_class = "Anomaly/Attack" # Assign a generic label
            # ... rest of the alert generation logic ...
        else:
            predicted_class = "Normal Traffic"
        ```
      - **K-Means:** Outputs a cluster ID. You'd need to have pre-determined which cluster IDs correspond to anomalous traffic based on your K-Means model evaluation.
        ```python
        # Example for K-Means
        cluster_id = self.model.predict(df)[0]
        anomalous_clusters = [0, 3] # Example: if clusters 0 and 3 were identified as anomalous
        if cluster_id in anomalous_clusters:
            predicted_class = "Anomaly/Attack (Cluster " + str(cluster_id) + ")"
            # ... rest of the alert generation logic ...
        else:
            predicted_class = "Normal Traffic"
        ```

6.  **Alert Log Filename (in `NetworkAnomalyGUI.add_alert`):**
    - You might want to change the output CSV filename to reflect the model being used.
      ```python
      # csv_file = os.path.join("nids_alerts", "nids_alerts_knn.csv")
      csv_file = os.path.join("nids_alerts", "nids_alerts_your_model_name.csv")
      ```

### General Considerations for Adaptation:

- **Feature Extraction (`extract_features` method):** This method is designed to extract features compatible with the CICIDS2017 dataset. If your new model was also trained on these features, this method should largely be reusable. If your model requires different features, this extensive method would need significant modification.
- **Model Training:** Ensure your new model is trained and saved correctly using `joblib` (or an appropriate library for its type).
- **Testing:** Thoroughly test any modifications with sample `pcap` files using `tcpreplay` to ensure the adapted prototype works as expected.

The core structure is quite modular, so adapting it should be a manageable task for someone familiar with Python and the machine learning libraries used.
