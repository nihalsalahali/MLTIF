# MLTIF: Multi-Layer Traffic Inspection Framework

**MLTIF** is a comprehensive, modular framework designed to detect and mitigate sophisticated multi-phase cyberattacks in Software-Defined IoT (SD-IoT) environments. It leverages real-time programmable data-plane analysis, advanced machine learning, and adaptive multi-controller coordination.

---

## 🌐 Framework Overview

MLTIF integrates the following three core components:

### 1. ITAM - Intelligent Traffic Analysis Module
- Implemented with P4 in `p4_itamodule/`
- Performs real-time, line-rate traffic feature extraction
- Metrics: entropy, payload size, TCP flags, etc.

### 2. ATDM - Advanced Threat Detection Module
- Located in `controller/atdm_module/`
- Lightweight ensemble of:
  - Shallow Decision Trees
  - Quantized CNNs
  - Spiking Neural Networks
- Uses temporal correlation for phase-aware detection

### 3. AMCM - Adaptive Mitigation and Collaboration Module
- Found in `controller/amcm_module/`
- Dynamically updates flow rules using P4
- Shares alerts and mitigation strategies across distributed SDN controllers

---

## 📁 Directory Structure

```bash
MLTIF_REBUILT/
├── README.md                  ← You are here
├── configs/                   ← JSON/YAML configurations
├── p4_itamodule/              ← ITAM P4 logic and helpers
├── controller/
│   ├── atdm_module/           ← ATDM ML models and detection logic
│   ├── amcm_module/           ← AMCM mitigation coordination
│   └── controllers/           ← Multi-controller implementation (e.g. Ryu, ONOS)
├── scripts/                   ← Launch, evaluation, and compilation scripts
```

---

## 🧪 Datasets Used

The framework is evaluated on:
- `CICIoT2023`
- `Edge-IIoTset`
- `HL-IoT`
- `TON_IoT`

---

## 🚀 How to Run

1. **Compile P4**:
   ```bash
   ./scripts/compile_p4.sh
   ```

2. **Deploy SDN Controllers**:
   ```bash
   ./scripts/deploy_controllers.sh
   ```

3. **Run Experiment**:
   ```bash
   ./scripts/run_experiment.sh
   ```

---

## 🛡️ Key Features

- Real-time traffic inspection with P4
- Ensemble ML for accurate multi-phase detection
- Adaptive mitigation with flow rule updates
- Multi-controller synchronization and resilience
- Deployment-ready and scalable

---

## 📜 License

MIT License. See `LICENSE` file.

---

## ✒️ Citation

If you use this framework, please cite the original MLTIF paper.

```
TBD: Add citation from the MLTIF paper.
```
