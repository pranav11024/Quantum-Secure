# Quantum-Secure: Hybrid Quantum-Classical Cryptographic Simulator

**Quantum-Secure** is an educational and research-oriented GUI tool that simulates hybrid quantum-classical secure communication using an extended BB84 protocol. It incorporates post-quantum authentication (Falcon-style), eavesdropping simulation, real-time QBER/entropy visualization, and secure messaging tailored for smart grid nodes.

---

## 🚀 Features

- **Extended BB84 Protocol**: Implements a visualized and secure key distribution using quantum bits with classical fallback.
- **Simulated MITM/Eavesdropping Attacks**: Demonstrates practical QKD vulnerabilities and countermeasures.
- **Post-Quantum Authentication**: Employs Falcon-style signature simulation for secure authentication.
- **Hybrid Key Agreement**: Combines quantum keys with classical X25519 Diffie-Hellman keys.
- **ChaCha20-Poly1305 Encryption**: Used for secure messaging between nodes after key exchange.
- **Smart Grid Nodes Simulation**: Includes various node types like control centers, meters, and sensors.
- **Live Visualization & Metrics**: Real-time graphs for QBER, entropy progression, and protocol performance.
- **MITM Detection Metrics**: Entropy saturation analysis and eavesdrop-error overlap detection.
- **GUI Built with Tkinter + Matplotlib**: Optimized for Windows and cross-platform support.

---

## 🖥️ Requirements

- Python 3.8+
- Qiskit
- NumPy
- Matplotlib
- SciPy
- Cryptography
- tkinter (included with standard Python installations)

Install dependencies:
```bash
pip install qiskit numpy matplotlib scipy cryptography
📂 Run the App
```bash
python Team6_CSEBsection_Code_KavithaCR.py
```
GUI will launch with options to:
Select nodes (Alice & Bob)
Set QKD parameters (key length, error rate)
Simulate attacks
Perform secure transmission post-key agreement

🛡️ Use Cases
Quantum Cryptography Demonstrations
Post-Quantum Hybrid Security Research
Smart Grid Security Simulations
Cryptographic Education & Visualization


📊 Sample Metrics Display
QBER (Quantum Bit Error Rate)
Key Rate (bits per second)
Entropy Saturation Step
Eavesdrop/Error Overlap Detection
MITM Alerts (Channel & Authentication Layer)
