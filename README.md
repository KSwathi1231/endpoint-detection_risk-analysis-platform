# AI-Driven Endpoint Defense Platform

An intelligent cybersecurity platform designed to detect, analyze, and assess potential endpoint threats using machine learning and contextual security analysis.

## Features

- Known threat detection using Random Forest
- Anomaly detection using Isolation Forest
- Behaviour-based analysis
- Context-aware risk scoring
- REST API using FastAPI
- Endpoint monitoring architecture
- Future support for IOC detection and automated response

## Machine Learning Models

### Random Forest Classifier
Used to classify network activity as:

- Normal
- Attack

### Isolation Forest
Used to identify anomalous or unusual network behaviour.

## Dataset

The project uses the UNSW-NB15 dataset for network intrusion detection.

## Project Architecture

```text
Network Event
      ↓
ML Service
├── Random Forest
└── Isolation Forest
      ↓
Behaviour Analysis
      ↓
Risk Engine
      ↓
Risk Score + Severity
