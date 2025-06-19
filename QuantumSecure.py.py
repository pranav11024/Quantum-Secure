import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
import base64
import random
import time
import hashlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scipy.stats import entropy
import os
import threading
import queue
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import uuid

# Constants
MIN_KEY_LENGTH = 128
MAX_KEY_LENGTH = 4096
MAX_MESSAGE_LENGTH = 1024  # Characters
QBER_THRESHOLD = 0.11      # Abort key if QBER exceeds 11%
APP_NAME = "Quantum-Secure"
FALCON_SIG_SIZE = 1330     # Size of a Falcon-512 signature (PQC)

class SimulatedFalcon:
    @staticmethod
    def keygen():
        """Generate a simulated Falcon key pair."""
        private_key = os.urandom(64)
        public_key = hashlib.shake_256(private_key).digest(64)
        return private_key, public_key
    
    @staticmethod
    def sign(message, private_key):
        """Create a simulated Falcon signature."""
        h = hmac.HMAC(private_key, hashes.SHA3_512())
        h.update(message)
        signature = h.finalize() + os.urandom(FALCON_SIG_SIZE - 64)
        return signature
    
    @staticmethod
    def verify(message, signature, public_key):
        """Verify a simulated Falcon signature."""
        # Simulated verification - in real implementation, we'd use actual PQC library
        h = hashlib.shake_256(message + public_key).digest(64)
        return hmac.compare_digest(signature[:64], h[:64])

def random_bitstring(length):
    return np.random.choice(['0', '1'], size=length).tolist()

def calculate_entropy(key):
    counts = np.array([key.count('0'), key.count('1')])
    if np.any(counts == 0):
        return 0
    return entropy(counts, base=2)

# Extended BB84 Protocol with Visualization and Authentication
def extended_bb84_protocol(alice_id, bob_id, length=256, error_rate=0.12,eavesdropping=False, update_callback=None,authentication_keys=None):
    simulator = AerSimulator(shots=1)
    alice_bits = random_bitstring(length)
    alice_bases = random_bitstring(length)
    bob_bases = random_bitstring(length)
    
    raw_key = []
    error_positions = []
    eavesdropped_bits = []
    error_rates = []
    entropy_values = []
    error_count = 0
    mitm_detected = False

    for i in range(length):
        qc = QuantumCircuit(1, 1)
        if alice_bits[i] == '1':
            qc.x(0)
        if alice_bases[i] == '1':
            qc.h(0)

        # Eavesdropping simulation (Eve or MITM attacker)
        if eavesdropping and random.random() < 0.5:
            eve_basis = random.choice(['0', '1'])
            if eve_basis == '1':
                qc.h(0)
            qc.measure(0, 0)
            qc = transpile(qc, simulator)
            result = simulator.run(qc).result()
            eve_bit = int(list(result.get_counts().keys())[0], 2)
            qc = QuantumCircuit(1, 1)  # Create new circuit
            if eve_bit:
                qc.x(0)
            if alice_bases[i] == '1':  # Try to restore the original basis
                qc.h(0)
            eavesdropped_bits.append(i)

        if bob_bases[i] == '1':
            qc.h(0)
        qc.measure(0, 0)

        qc = transpile(qc, simulator, optimization_level=3)
        result = simulator.run(qc).result()
        bob_bit = list(result.get_counts().keys())[0]

        # Channel noise simulation
        if random.random() < error_rate:
            bob_bit = '1' if bob_bit == '0' else '0'

        # Check matching bases
        if alice_bases[i] == bob_bases[i]:
            raw_key.append((alice_bits[i], bob_bit))
            if alice_bits[i] != bob_bit:
                error_count += 1
                error_positions.append(i)
            current_key = [a for a, _ in raw_key]
            current_error_rate = error_count / len(raw_key) if raw_key else 0
            error_rates.append(current_error_rate)
            entropy_val = calculate_entropy(''.join(current_key))
            entropy_values.append(entropy_val)
        
        if update_callback is not None:
            update_callback(alice_id, bob_id, i, alice_bits, alice_bases, bob_bases, bob_bit,eavesdropped=(i in eavesdropped_bits))
    
    qber = len(error_positions) / len(raw_key) if raw_key else 1.0
    
    # Authentication phase using post-quantum signatures
    if authentication_keys and qber < QBER_THRESHOLD:
        try:
            # Alice signs her bases choices and sends to Bob
            alice_auth_data = ''.join(alice_bases).encode()
            alice_sig = SimulatedFalcon.sign(alice_auth_data, authentication_keys['alice_private'])
            
            # Simulate Bob verifying Alice's signature
            if not SimulatedFalcon.verify(alice_auth_data, alice_sig, authentication_keys['alice_public']):
                mitm_detected = True
                
            # Bob signs his bases choices and sends to Alice
            bob_auth_data = ''.join(bob_bases).encode()
            bob_sig = SimulatedFalcon.sign(bob_auth_data, authentication_keys['bob_private'])
            
            # Simulate Alice verifying Bob's signature
            if not SimulatedFalcon.verify(bob_auth_data, bob_sig, authentication_keys['bob_public']):
                mitm_detected = True
        except Exception:
            mitm_detected = True
    
    return raw_key, error_positions, eavesdropped_bits, error_rates, entropy_values, mitm_detected

def cascade_error_correction(raw_key, rounds=4):
    sifted_bits = [int(b[0]) for b in raw_key]
    received_bits = [int(b[1]) for b in raw_key]
    block_size = len(sifted_bits) // rounds if rounds > 0 else len(sifted_bits)
    
    for _ in range(rounds):
        for i in range(0, len(sifted_bits), block_size):
            block = slice(i, min(i + block_size, len(sifted_bits)))
            parity_alice = sum(sifted_bits[block]) % 2
            parity_bob = sum(received_bits[block]) % 2
            
            if parity_alice != parity_bob:
                for j in range(block.start, block.stop):
                    if sifted_bits[j] != received_bits[j]:
                        received_bits[j] = sifted_bits[j]
                        break
        block_size = max(1, block_size // 2)
    return received_bits

def privacy_amplification(key_bits, output_bytes):
    """Convert key bits to secure key using SHA3-256 as a randomness extractor"""
    bit_string = ''.join(map(str, key_bits))
    return hashlib.sha3_256(bit_string.encode()).digest()[:output_bytes]

def hybrid_key_agreement(qkd_key, classical_key):
    """Combine quantum and classical keys for hybrid security"""
    combined = bytes([a ^ b for a, b in zip(qkd_key, classical_key)])
    return HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=None,
        info=b'hybrid_key_agreement',
    ).derive(combined)

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def chacha20_encrypt(data, key):
    """Encrypt using ChaCha20-Poly1305 with a 12-byte nonce"""
    if isinstance(data, str):
        data = data.encode()
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, data, None)
    return base64.b64encode(nonce + ciphertext).decode()

def chacha20_decrypt(encrypted_data, key):
    """Decrypt using ChaCha20-Poly1305"""
    decoded = base64.b64decode(encrypted_data)
    nonce, ciphertext = decoded[:12], decoded[12:]
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


class SmartGridNode:
    def __init__(self, node_id, name, node_type):
        self.node_id = node_id
        self.name = name
        self.node_type = node_type  # "control", "substation", "meter", "sensor"
        self.keys = {}  # Shared keys with other nodes
        self.quantum_keys = {}  # Raw quantum keys before hybridization
        self.classical_keys = {}  # Classical keys from X25519
        self.pqc_keys = {}  # Post-quantum authentication keys
        self.status = "online"  # online, offline, compromised
        self.session_id = str(uuid.uuid4())[:8]
        self.historical_qber = []
        
    def generate_pqc_keypair(self):
        """Generate post-quantum keypair for authentication"""
        private_key, public_key = SimulatedFalcon.keygen()
        return {
            'private': private_key,
            'public': public_key
        }
    
    def generate_classical_keypair(self):
        """Generate X25519 keypair for classical key exchange"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return {
            'private': private_key,
            'public': public_key
        }
    
    def agree_on_classical_key(self, private_key, peer_public_key):
        """Perform Diffie-Hellman key agreement"""
        shared_key = private_key.exchange(peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'classical_key_agreement',
        ).derive(shared_key)

class QuantumCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME}")

        try:
            self.root.iconbitmap(default="app.ico")
        except:
            pass
        
        self.root.state('zoomed')  # Maximize window on Windows
        self.root.minsize(1250, 700)  # Minimum size
        
        
        # Initialize nodes with node types
        self.nodes = [
            SmartGridNode(0, "Control Center", "control"),
            SmartGridNode(1, "Substation Alpha", "substation"),
            SmartGridNode(2, "Substation Beta", "substation"),
            SmartGridNode(3, "Smart Meter 101", "meter"),
            SmartGridNode(4, "Smart Meter 102", "meter"),
            SmartGridNode(5, "Wind Turbine Sensor", "sensor"),
            SmartGridNode(6, "Solar Array Controller", "sensor"),
        ]
        
        # Initialize variables
        self.selected_alice = tk.StringVar()
        self.selected_bob = tk.StringVar()
        self.key_length_var = tk.IntVar()
        self.error_rate_var = tk.DoubleVar()
        self.eavesdropping_var = tk.BooleanVar()
        self.classical_hybrid_var = tk.BooleanVar()
        self.pqc_auth_var = tk.BooleanVar()
        self.mitm_protection_var = tk.BooleanVar()
        self.windows_optimization_var = tk.BooleanVar()

        
        # Initialize performance metrics history
        self.metrics_history = {
            'qber': [],
            'key_rate': [],
            'time': [],
            'errors': [],
            'eavesdropped': [],
            'mitm_attempts': [],
            'hybrid_strength': [],
            'entropy_saturation_step': [],
            'eavesdrop_overlap': [],
        }
        
        # Worker queue for background operations
        self.work_queue = queue.Queue()
        self.worker_thread = None
        
        # Debug flag
        self.debug_mode = False
        
        self.setup_variables()
        self.setup_gui()
        self.initialize_background_worker()
    

    def show_historical_metrics(self):
        """Display historical performance metrics in a new window"""
        if not self.metrics_history['qber']:
            self.log("No historical data available")
            return
        
        hist_window = tk.Toplevel(self.root)
        hist_window.title("Historical Performance Metrics")
        hist_window.geometry("1000x800")
        
        fig = plt.Figure(figsize=(10, 8))
        ax = fig.add_subplot(111)
        
        sessions = range(1, len(self.metrics_history['qber']) + 1)
        ax.plot(sessions, self.metrics_history['qber'], 'r-o', label='QBER')
        ax.plot(sessions, self.metrics_history['key_rate'], 'b-^', label='Key Rate')
        ax.plot(sessions, self.metrics_history['mitm_attempts'], 'g--s', label='MITM Attempts')
        if self.metrics_history['eavesdrop_overlap']:
            ax.plot(sessions, [v * 100 for v in self.metrics_history['eavesdrop_overlap']], 
                    'm--d', label='Eavesdrop Overlap (%)')
        
        
        ax.set_title("Historical Performance Metrics")
        ax.set_xlabel("Session Number")
        ax.set_ylabel("Value")
        ax.legend()
        ax.grid(True)
        
        canvas = FigureCanvasTkAgg(fig, master=hist_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()

    def show_graph_window(self, error_rates, entropy_values):
        """Display error rate and entropy graphs with saturation point"""
        graph_window = tk.Toplevel(self.root)
        graph_window.title("Protocol Performance Metrics")
        graph_window.geometry("900x700")
    
        fig = plt.Figure(figsize=(10, 9))
        ax1 = fig.add_subplot(211)
        ax2 = fig.add_subplot(212)
    
        steps = list(range(len(error_rates)))
    
        # Plot QBER
        ax1.plot(steps, error_rates, color='crimson', linestyle='-', linewidth=2, marker='o', label='QBER')
        ax1.axhline(y=QBER_THRESHOLD, color='orange', linestyle='--', linewidth=1.5, label=f'Threshold ({QBER_THRESHOLD:.2})')
        if error_rates:
            max_idx = int(np.argmax(error_rates))
            ax1.plot(max_idx, error_rates[max_idx], 'ko', label='Max QBER')
            ax1.annotate(f'{error_rates[max_idx]:.3f}', xy=(max_idx, error_rates[max_idx]),
                         xytext=(max_idx + 1, error_rates[max_idx] + 0.01),
                         arrowprops=dict(arrowstyle='->', color='black'))
    
        ax1.set_xlabel("Protocol Step")
        ax1.set_ylabel("Error Rate (QBER)")
        ax1.set_title("Quantum Bit Error Rate Progression")
        ax1.grid(True, linestyle='--', alpha=0.6)
        ax1.legend()
    
        # Plot Entropy
        ax2.plot(steps, entropy_values, color='navy', linestyle='-', linewidth=2, marker='^', label='Entropy')
    
        # Entropy Saturation Threshold
        entropy_threshold = 0.95
        ax2.axhline(y=entropy_threshold, color='green', linestyle='--', linewidth=1.5, label='Entropy Threshold (0.95)')
    
        # Mark first entropy saturation point
        saturation_step = next((i for i, e in enumerate(entropy_values) if e >= entropy_threshold), None)
        if saturation_step is not None:
            ax2.plot(saturation_step, entropy_values[saturation_step], 'ko', label='Saturation Step')
            ax2.annotate(f'{entropy_values[saturation_step]:.2f} at step {saturation_step}', 
                         xy=(saturation_step, entropy_values[saturation_step]),
                         xytext=(saturation_step + 1, entropy_values[saturation_step] + 0.1),
                         arrowprops=dict(arrowstyle='->', color='black'))
        else:
            # Add annotation that saturation was not reached
            ax2.text(0.5, 0.5, 'Entropy saturation threshold not reached',
                    transform=ax2.transAxes, fontsize=12, ha='center',
                    bbox=dict(boxstyle='round', facecolor='lightcoral', alpha=0.5))
    
        ax2.set_xlabel("Protocol Step")
        ax2.set_ylabel("Shannon Entropy")
        ax2.set_title("Key Entropy Progression")
        ax2.grid(True, linestyle='--', alpha=0.6)
        ax2.legend()
    
        fig.tight_layout()
    
        canvas = FigureCanvasTkAgg(fig, master=graph_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
        # Add text display of key metrics at the bottom
        if error_rates and entropy_values:
            overlap_ratio = self.metrics_history['eavesdrop_overlap'][-1] if self.metrics_history['eavesdrop_overlap'] else 0
            metrics_frame = ttk.Frame(graph_window)
            metrics_frame.pack(fill=tk.X, padx=10, pady=5)
            ttk.Label(metrics_frame, text=f"Eavesdrop-Error Overlap: {overlap_ratio*100:.2f}% | " + 
                                 f"Entropy Saturation Step: {saturation_step if saturation_step is not None else 'Not reached'}",
                     font=("Arial", 10, "bold")).pack(fill=tk.X)

    
    def secure_transmission(self):
        """Handle secure message transmission between nodes"""
        try:
            alice = next(n for n in self.nodes if n.name == self.selected_alice.get())
            bob = next(n for n in self.nodes if n.name == self.selected_bob.get())
            
            if bob.node_id not in alice.keys:
                raise ValueError("No shared key between selected nodes")
            
            key = alice.keys[bob.node_id]
            message = self.message_entry.get()
            
            if not message:
                raise ValueError("Please enter a message to encrypt")
            if len(message) > MAX_MESSAGE_LENGTH:
                raise ValueError(f"Message exceeds {MAX_MESSAGE_LENGTH} character limit")
            
            # Encrypt and decrypt to verify security
            start_time = time.time()
            encrypted = chacha20_encrypt(message, key)
            decrypted = chacha20_decrypt(encrypted, key)

            duration = time.time() - start_time
            
            # Display results
            self.log(f"Encryption Time: {duration*1000:.2f}ms")
            self.log(f"Encrypted: {encrypted}...")
            self.log(f"Decrypted: {decrypted}")
            
            self.result_label.config(
                text=f"Secure transmission successful!\nEncrypted: {encrypted}",
                foreground="green"
            )
            
            # Update metrics
            self.metrics_history.setdefault('encryption_times', []).append(duration)
            
        except Exception as e:
            self.log(f"Transmission failed: {str(e)}")
            self.result_label.config(
                text="Transmission failed! Check key exchange first.",
                foreground="red"
            )
            messagebox.showerror("Transmission Error", str(e))
    
    def setup_variables(self):
        """Initialize default values for variables"""
        self.selected_alice.set(self.nodes[0].name)
        self.selected_bob.set(self.nodes[1].name)
        self.key_length_var.set(512)
        self.error_rate_var.set(0.08)
        self.eavesdropping_var.set(False)
        self.classical_hybrid_var.set(True)
        self.pqc_auth_var.set(True)
        self.mitm_protection_var.set(True)
        self.windows_optimization_var.set(True)


    def setup_gui(self):
        """Create the application GUI"""
        # Create main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create a notebook for tabbed interface
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: QKD Control
        qkd_tab = ttk.Frame(notebook)
        notebook.add(qkd_tab, text="QKD Control")
        self.setup_qkd_tab(qkd_tab)
        # Status bar
        self.status_bar = ttk.Label(main_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_qkd_tab(self, parent):
        """Setup QKD control tab"""
        # Node selection frame
        node_frame = ttk.LabelFrame(parent, text="Node Selection")
        node_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(node_frame, text="Sender (Alice):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        alice_combo = ttk.Combobox(node_frame, textvariable=self.selected_alice, values=[n.name for n in self.nodes], width=30)
        alice_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(node_frame, text="Receiver (Bob):").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        bob_combo = ttk.Combobox(node_frame, textvariable=self.selected_bob, values=[n.name for n in self.nodes], width=30)
        bob_combo.grid(row=0, column=3, padx=5, pady=5)
        
        # Protocol parameters frame
        param_frame = ttk.LabelFrame(parent, text="Protocol Parameters")
        param_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(param_frame, text="Key Length (bits):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        key_length_spin = ttk.Spinbox(param_frame, from_=MIN_KEY_LENGTH, to=MAX_KEY_LENGTH, increment=128,textvariable=self.key_length_var, width=10)
        key_length_spin.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(param_frame, text="Error Rate:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        error_rate_spin = ttk.Spinbox(param_frame, from_=0.0, to=0.3, increment=0.01,textvariable=self.error_rate_var, width=10)
        error_rate_spin.grid(row=0, column=3, padx=5, pady=5)
        
        # Security options frame
        security_frame = ttk.LabelFrame(param_frame, text="Security Options")
        security_frame.grid(row=1, column=0, columnspan=4, sticky="ew", padx=5, pady=5)
        
        ttk.Checkbutton(security_frame, text="Simulate Eavesdropping (MITM Attack)",variable=self.eavesdropping_var).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(security_frame, text="Use Classical-Quantum Hybrid Mode",variable=self.classical_hybrid_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(security_frame, text="Enable Post-Quantum Authentication",variable=self.pqc_auth_var).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(security_frame, text="Enable MITM Protection",variable=self.mitm_protection_var).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Button frame
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Generate Quantum Key", command=self.run_qkd, width=25).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Secure Transmission",command=self.secure_transmission, width=25).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset Key Material",command=self.reset_keys, width=25).pack(side=tk.LEFT, padx=5)

        
        # Output and metrics section
        output_frame = ttk.LabelFrame(parent, text="Protocol Output")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Performance metrics
        perf_frame = ttk.LabelFrame(parent, text="Performance Metrics")
        perf_frame.pack(fill=tk.X, pady=5)
        
        self.metrics_label = ttk.Label(perf_frame, text="No data available")
        self.metrics_label.pack(fill=tk.X, padx=5, pady=5)
        
        # Message frame
        msg_frame = ttk.LabelFrame(parent, text="Secure Messaging")
        msg_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(msg_frame, text="Message:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.message_entry = ttk.Entry(msg_frame, width=80)
        self.message_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(msg_frame, text="Clear", command=lambda: self.message_entry.delete(0, tk.END)).grid(row=0, column=2, padx=5, pady=5)
        
        # Result frame
        result_frame = ttk.LabelFrame(parent, text="Operation Result")
        result_frame.pack(fill=tk.X, pady=5)
        
        self.result_label = ttk.Label(result_frame, text="")
        self.result_label.pack(fill=tk.X, padx=5, pady=5)




    def log(self, message):
        """Add message to output log"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.output_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.output_text.see(tk.END)
        if hasattr(self, 'status_bar'):
            self.status_bar.config(text=f"Last action: {message}")
        self.root.update_idletasks()

    def update_status(self, message):
        """Update status bar message"""
        self.status_bar.config(text=message)
        self.root.update_idletasks()

    def initialize_background_worker(self):
        """Initialize background worker thread for non-UI operations"""
        def worker():
            while True:
                try:
                    task, args, callback = self.work_queue.get()
                    if task == "stop":
                        break
                    result = task(*args)
                    self.root.after(0, lambda: callback(result))
                except Exception as e:
                    self.root.after(0, lambda: self.log(f"Worker error: {str(e)}"))
                finally:
                    self.work_queue.task_done()
        
        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def queue_task(self, task, args, callback):
        """Queue a task for background execution"""
        self.work_queue.put((task, args, callback))
    
    def detect_mitm_quantum_channel(self, error_positions, eavesdropped_bits):
        """Detect MITM attacks by analyzing error patterns in the quantum channel"""
        try:
            if not error_positions or not eavesdropped_bits:
                return False
            
            # Calculate correlation between error positions and eavesdropped positions
            error_set = set(error_positions)
            eavesdropped_set = set(eavesdropped_bits)
            overlap = len(error_set & eavesdropped_set)
            
            # If more than 25% of errors coincide with eavesdropped bits, likely MITM
            correlation = overlap / len(error_positions)
            threshold = 0.25
            
            self.log(f"Quantum channel MITM detection: Error-Eavesdrop correlation = {correlation:.2f}")
            
            if correlation > threshold:
                self.log("WARNING: Quantum channel analysis suggests MITM attack!")
                self.metrics_history.setdefault('quantum_mitm_detections', []).append(1)
                return True
            return False
        
        except Exception as e:
            self.log(f"MITM detection error: {str(e)}")
            return False
        
    
    def run_qkd(self):
        """Run the quantum key distribution protocol"""
        try:
            alice_name = self.selected_alice.get()
            bob_name = self.selected_bob.get()
            
            if alice_name == bob_name:
                raise ValueError("Sender and receiver must be different nodes")
            
            alice = next(n for n in self.nodes if n.name == alice_name)
            bob = next(n for n in self.nodes if n.name == bob_name)
            
            # Generate classical key pairs if hybrid mode is enabled
            if self.classical_hybrid_var.get():
                self.log(f"Generating classical key pairs for {alice.name} and {bob.name}...")
                alice_classical = alice.generate_classical_keypair()
                bob_classical = bob.generate_classical_keypair()
                
                # Exchange public keys (simulated)
                alice_pub = alice_classical['public']
                bob_pub = bob_classical['public']
                
                # Compute shared classical keys
                alice_shared = alice.agree_on_classical_key(alice_classical['private'], bob_pub)
                bob_shared = bob.agree_on_classical_key(bob_classical['private'], alice_pub)
                
                # Store classical keys
                alice.classical_keys[bob.node_id] = alice_shared
                bob.classical_keys[alice.node_id] = bob_shared
                self.log("Classical key exchange completed successfully")
            
            # Generate post-quantum authentication keys if enabled
            auth_keys = None
            if self.pqc_auth_var.get():
                self.log("Generating post-quantum authentication keys...")
                alice_pqc = alice.generate_pqc_keypair()
                bob_pqc = bob.generate_pqc_keypair()
                auth_keys = {
                    'alice_private': alice_pqc['private'],
                    'alice_public': alice_pqc['public'],
                    'bob_private': bob_pqc['private'],
                    'bob_public': bob_pqc['public']
                }
                self.log("Post-quantum authentication keys generated")
    
            # Prepare visualization window
            vis_window = tk.Toplevel(self.root)
            vis_window.title("Quantum Key Generation Visualization")
            fig = plt.Figure(figsize=(8, 4))
            ax = fig.add_subplot(111)
            ax.set_xlabel("Key Bit Index")
            ax.set_ylabel("Bit Value")
            ax.set_ylim(-0.5, 1.5)
            ax.set_title("Key Generation Process (Key Bits Only)")
            canvas = FigureCanvasTkAgg(fig, master=vis_window)
            canvas.get_tk_widget().pack()
    
            key_indices = []
            alice_key_bits = []
            bob_key_bits = []
            bob_colors = []

            def update_visualization(alice_id, bob_id, step, alice_bits, alice_bases, bob_bases, bob_bit, eavesdropped):
                message = f"Step {step+1}: Alice bit {alice_bits[step]} | Bob basis {bob_bases[step]} | Measured {bob_bit}"
                if eavesdropped:
                    message += " (Eavesdropped)"
                self.log(message)
                
                if alice_bases[step] == bob_bases[step]:
                    key_indices.append(step)
                    alice_key_bits.append(int(alice_bits[step]))
                    bob_key_bits.append(int(bob_bit))
                    bob_colors.append("red" if alice_bits[step] != bob_bit else "blue")
                    ax.clear()
                    ax.set_xlabel("Key Bit Index")
                    ax.set_ylabel("Bit Value")
                    ax.set_ylim(-0.5, 1.5)
                    ax.set_title("Key Generation Process (Key Bits Only)")
                    ax.scatter(key_indices, alice_key_bits, color="green", marker="o", label="Alice")
                    ax.scatter(key_indices, bob_key_bits, color=bob_colors, marker="x", label="Bob")
                    ax.legend()
                    canvas.draw()
                    self.root.update()
                    time.sleep(0.0001)

            # Run extended BB84 protocol with authentication
            start_time = time.time()
            raw_key, errors, eavesdropped, error_rates, entropy_values, mitm_detected = extended_bb84_protocol(
                alice.node_id, bob.node_id,
                length=self.key_length_var.get(),
                error_rate=self.error_rate_var.get(),
                eavesdropping=self.eavesdropping_var.get(),
                update_callback=update_visualization,
                authentication_keys=auth_keys
            )
            
            duration = time.time() - start_time
            qber = len(errors) / len(raw_key) if raw_key else 1.0
            
            # Calculate Eavesdrop Overlap % - ALWAYS CALCULATE THIS
            if errors and eavesdropped:
                overlap_ratio = len(set(errors) & set(eavesdropped)) / len(errors)
            else:
                overlap_ratio = 0.0
            self.metrics_history['eavesdrop_overlap'].append(overlap_ratio)
            self.log(f"Eavesdrop-Error Overlap: {overlap_ratio*100:.2f}%")
            
            # Compute Entropy Saturation Step - ALWAYS CALCULATE THIS
            entropy_threshold = 0.95
            saturation_step = next((i for i, e in enumerate(entropy_values) if e >= entropy_threshold), -1)
            self.metrics_history['entropy_saturation_step'].append(saturation_step)
            self.log(f"Entropy saturation step (>= {entropy_threshold}): {saturation_step if saturation_step != -1 else 'Not reached'}")
            
            # Check for MITM attacks
            if mitm_detected and self.mitm_protection_var.get():
                self.log("MITM attack detected during authentication!")
                self.show_graph_window(error_rates, entropy_values)
                messagebox.showerror("Security Breach", "MITM attack detected! Key exchange aborted.")
                
                # Update metrics even in failure case
                self.show_realtime_metrics(qber, 0, len(errors), len(eavesdropped), overlap_ratio, saturation_step)
                return
            
            quantum_mitm = self.detect_mitm_quantum_channel(errors, eavesdropped)
            if quantum_mitm and self.mitm_protection_var.get():
                self.log("MITM attack detected via quantum channel monitoring!")
                self.show_graph_window(error_rates, entropy_values)
                messagebox.showerror("Security Breach", 
                                    "Quantum channel analysis detected MITM attack! Key exchange aborted.")
                self.metrics_history.setdefault('quantum_mitm_detections', []).append(1)
                
                # Update metrics even in failure case
                self.show_realtime_metrics(qber, 0, len(errors), len(eavesdropped), overlap_ratio, saturation_step)
                return
            
            if qber > QBER_THRESHOLD:
                key_rate = 0
                self.log(f"QBER too high ({qber:.2%}), key rejected")
                # Still show metrics even when key is rejected
                self.show_realtime_metrics(qber, key_rate, len(errors), len(eavesdropped), overlap_ratio, saturation_step)
            else:
                # Perform error correction and privacy amplification
                corrected_bits = cascade_error_correction(raw_key)
                quantum_key = privacy_amplification(corrected_bits, 32)
                
                # Create hybrid key if enabled
                if self.classical_hybrid_var.get():
                    classical_key = alice.classical_keys[bob.node_id]
                    final_key = hybrid_key_agreement(quantum_key, classical_key)
                    self.log("Hybrid quantum-classical key created")
                else:
                    final_key = quantum_key
                
                key_rate = (len(final_key) * 8) / duration if duration > 0 else 0
                
                # Store keys in both nodes
                alice.keys[bob.node_id] = final_key
                bob.keys[alice.node_id] = final_key
                self.log("Key distribution completed successfully")
                
                # Update metrics in success case
                self.show_realtime_metrics(qber, key_rate, len(errors), len(eavesdropped), overlap_ratio, saturation_step)
    
            # Update metrics and show graphs
            self.show_graph_window(error_rates, entropy_values)
            
            metrics = (
                f"Time: {duration:.2f}s | QBER: {qber:.2%} | "
                f"Key Rate: {key_rate:.2f} bps\n"
                f"Errors Detected: {len(errors)} | "
                f"Eavesdropped Bits: {len(eavesdropped)} | "
                f"Eavesdrop-Error Overlap: {overlap_ratio*100:.2f}% | "
                f"Entropy Saturation: {'Step ' + str(saturation_step) if saturation_step != -1 else 'Not reached'} | "
                f"MITM Protection: {'Active' if self.mitm_protection_var.get() else 'Inactive'}"
            )
            
            self.metrics_history['eavesdropped'].append(len(eavesdropped))
            self.metrics_history['qber'].append(qber)
            self.metrics_history['key_rate'].append(key_rate)
            self.metrics_history['time'].append(duration)
            self.metrics_history['errors'].append(len(errors))
            self.metrics_history['mitm_attempts'].append(1 if mitm_detected else 0)
            
            self.metrics_label.config(text=metrics)
            
            if qber > QBER_THRESHOLD:
                messagebox.showerror("QKD Failed", f"QBER ({qber:.2%}) exceeds acceptable threshold.")
            else:
                self.result_label.config(text="Key exchange successful!", foreground="green")
    
        except Exception as e:
            self.log(f"Error in QKD protocol: {str(e)}")
            self.result_label.config(text="Key exchange failed!", foreground="red")
            messagebox.showerror("Protocol Error", f"Key exchange failed: {str(e)}")

    def reset_keys(self):
        """Reset all keys for selected nodes"""
        alice = next(n for n in self.nodes if n.name == self.selected_alice.get())
        bob = next(n for n in self.nodes if n.name == self.selected_bob.get())
        
        alice.keys = {}
        bob.keys = {}
        alice.classical_keys = {}
        bob.classical_keys = {}
        self.log(f"Reset all keys for {alice.name} and {bob.name}")
        self.result_label.config(text="Keys reset successfully", foreground="blue")

    def show_realtime_metrics(self, qber, key_rate, errors, eavesdropped, overlap_ratio=0, saturation_step=-1):
        """Enhanced metrics display that always includes overlap and saturation metrics"""
        fig = plt.Figure(figsize=(10, 6))
        ax = fig.add_subplot(111)
        
        metrics = [qber * 100, key_rate, errors, eavesdropped, overlap_ratio * 100]
        labels = ['QBER (%)', 'Key Rate (bps)', 'Errors', 'Eavesdropped', 'Overlap (%)']
        bars = ax.bar(labels, metrics)
        
        # Color coding
        bars[0].set_color('crimson' if qber > QBER_THRESHOLD else 'green')
        bars[4].set_color('orange' if overlap_ratio > 0.25 else 'lightblue')
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2f}',
                    ha='center', va='bottom')
        
        # Add entropy saturation annotation
        if saturation_step != -1:
            ax.text(0.5, 0.95, f'Entropy saturation step: {saturation_step}', 
                    transform=ax.transAxes, ha='center', va='top',
                    bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        else:
            ax.text(0.5, 0.95, 'Entropy saturation: Not reached', 
                    transform=ax.transAxes, ha='center', va='top',
                    bbox=dict(boxstyle='round', facecolor='lightcoral', alpha=0.5))
        
        ax.set_title("Current Session Metrics")
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        
        metrics_window = tk.Toplevel(self.root)
        metrics_window.title("Session Metrics")
        canvas = FigureCanvasTkAgg(fig, master=metrics_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = QuantumCryptoApp(root)
    root.mainloop()
