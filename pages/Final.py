import streamlit as st
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error, r2_score

# Application Title
st.title("Modeling and Simulation with Python")

# Sidebar for User Input
st.sidebar.header("Data Generation Settings")

# User Inputs for Data Generation
num_samples = st.sidebar.slider("Number of Samples", min_value=100, max_value=5000, value=1000)
feature1_mean = st.sidebar.number_input("Mean of Feature1", value=0.0)
feature1_std = st.sidebar.number_input("Standard Deviation of Feature1", value=1.0)

# Generate Synthetic Data
np.random.seed(42)
data = {
    'Feature1': np.random.normal(feature1_mean, feature1_std, num_samples),
    'Feature2': np.random.uniform(0, 10, num_samples),
    'Feature3': np.random.exponential(1, num_samples)
}
df = pd.DataFrame(data)

# Display Data
st.header("Generated Data")
st.write(df.head())

# Exploratory Data Analysis
st.header("Exploratory Data Analysis")

# Summary Statistics
st.subheader("Summary Statistics")
st.write(df.describe())

# Visualizations
st.subheader("Visualizations")

# Distribution Plot
st.write("Distribution of Feature1")
fig, ax = plt.subplots()
sns.histplot(df['Feature1'], kde=True, ax=ax)
st.pyplot(fig)

# Correlation Heatmap
st.write("Correlation Matrix")
fig, ax = plt.subplots()
sns.heatmap(df.corr(), annot=True, cmap='coolwarm', ax=ax)
st.pyplot(fig)

# Modeling
st.header("Modeling")

# Define Features and Target
X = df[['Feature1', 'Feature2']]
y = df['Feature3']

# Linear Regression Model
model = LinearRegression()
model.fit(X, y)

# Display Model Coefficients
st.subheader("Model Coefficients")
st.write(f"Coefficients: {model.coef_}")
st.write(f"Intercept: {model.intercept_}")

# Simulation
st.header("Simulation")

# Simulate Outcomes
predictions = model.predict(X)
df['Predicted_Feature3'] = predictions

# Display Predictions
st.write(df[['Feature3', 'Predicted_Feature3']].head())

# Evaluation and Analysis
st.header("Evaluation and Analysis")

# Evaluation Metrics
mse = mean_squared_error(df['Feature3'], df['Predicted_Feature3'])
r2 = r2_score(df['Feature3'], df['Predicted_Feature3'])

st.subheader("Evaluation Metrics")
st.write(f"Mean Squared Error: {mse}")
st.write(f"R-squared: {r2}")

# Actual vs Predicted Plot
st.subheader("Actual vs Predicted")
fig, ax = plt.subplots()
sns.scatterplot(x='Feature3', y='Predicted_Feature3', data=df, ax=ax)
ax.set_title('Actual vs Predicted')
st.pyplot(fig)

# Conclusion
st.header("Conclusion")
st.write("This Streamlit application demonstrates the essential steps in modeling and simulation using Python. Users can generate synthetic data, explore it, apply a model, and evaluate its performance interactively.")