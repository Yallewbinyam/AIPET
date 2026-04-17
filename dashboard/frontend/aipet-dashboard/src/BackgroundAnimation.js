import React, { useEffect, useRef, useState } from "react";
import ReactDOM from "react-dom/client";

const THEMES = [
  { id: "radar",      label: "Mission Control", icon: "📡", color: "#00ff88" },
  { id: "neural",     label: "Neural Network",  icon: "🧠", color: "#a78bfa" },
  { id: "storm",      label: "Threat Storm",    icon: "⛈️", color: "#ff3b5c" },
  { id: "starfield",  label: "Deep Space",      icon: "🌌", color: "#a78bfa" },
  { id: "pulse",      label: "Pulse Grid",      icon: "💫", color: "#00e5ff" },
  { id: "threatmap",  label: "Threat Map",      icon: "🗺️", color: "#ff3b5c" },
  { id: "binary",     label: "Binary Stream",   icon: "01", color: "#7c3aed" },
  { id: "none",       label: "No Animation",    icon: "⬛", color: "#334155" },
];

function BackgroundSystem() {
  const canvasRef = useRef(null);
  const animRef   = useRef(null);
  const [theme, setTheme] = useState(
    () => localStorage.getItem("aipet_theme") || "radar"
  );
  const [open, setOpen] = useState(false);

  const selectTheme = (id) => {
    setTheme(id);
    localStorage.setItem("aipet_theme", id);
    setOpen(false);
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let W = canvas.width  = window.innerWidth;
    let H = canvas.height = window.innerHeight;
    const s = {};

    const onResize = () => {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
      init();
    };
    window.addEventListener("resize", onResize);

    function init() {
      Object.keys(s).forEach(k => delete s[k]);

      if (theme === "none") return;

      if (theme === "pulse") {
        s.rings = Array(8).fill(0).map((_,i) => ({
          r: (i/8) * Math.min(W,H) * 0.7,
          speed: 0.3 + Math.random()*0.4,
          maxR: Math.min(W,H) * 0.75,
          alpha: 0.8 - i*0.08,
          color: i%2===0 ? "#00e5ff" : "#a78bfa",
        }));
        s.cx = W/2; s.cy = H/2;
        s.nodes = Array(12).fill(0).map(() => ({
          angle: Math.random()*Math.PI*2,
          dist: 80+Math.random()*Math.min(W,H)*0.3,
          pulse: Math.random()*Math.PI*2,
          color: ["#00e5ff","#00ff88","#a78bfa"][Math.floor(Math.random()*3)],
        }));
      }

      else if (theme === "threatmap") {
        s.nodes = Array(15).fill(0).map(() => ({
          x: Math.random()*W, y: Math.random()*H,
          r: 2+Math.random()*3,
          color: Math.random()>0.3 ? "#ff3b5c" : "#00e5ff",
          pulse: Math.random()*Math.PI*2,
          pSpeed: 0.02+Math.random()*0.02,
        }));
        s.connections = [];
        s.conTimer = 0;
        s.packets = [];
      }

      else if (theme === "binary") {
        s.cols  = Math.floor(W / 20);
        s.drops = Array(s.cols).fill(0).map(() => ({
          y: Math.random() * H,
          speed: 0.3 + Math.random()*0.5,
          alpha: 0.3 + Math.random()*0.4,
          color: Math.random()>0.5 ? "#7c3aed" : "#a78bfa",
        }));
      }

      else if (theme === "neural") {
        s.nodes = Array(50).fill(0).map((_, i) => ({
          x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random()-0.5)*0.35, vy: (Math.random()-0.5)*0.35,
          r: 2 + Math.random()*3,
          color: ["#a78bfa","#7c3aed","#00e5ff","#00ff88"][Math.floor(Math.random()*4)],
          pulse: Math.random() * Math.PI * 2,
          pSpeed: 0.02 + Math.random()*0.02,
          layer: Math.floor(Math.random()*3),
        }));
        s.signals = [];
        s.sigTimer = 0;
      }

      else if (theme === "storm") {
        s.particles = Array(120).fill(0).map(() => ({
          x: Math.random()*W, y: Math.random()*H,
          vx: (Math.random()-0.5)*2, vy: -1-Math.random()*3,
          r: 0.5+Math.random()*2.5,
          color: ["#ff3b5c","#ff8c00","#ff3b5c","#ffd600"][Math.floor(Math.random()*4)],
          trail: [],
        }));
        s.ltTimer = 0;
        s.flashAlpha = 0;
      }





      else if (theme === "starfield") {
        s.stars = Array(200).fill(0).map(() => ({
          x: Math.random()*W, y: Math.random()*H,
          z: Math.random()*W,
          pz: 0,
          color: ["#ffffff","#00e5ff","#a78bfa","#00ff88"][Math.floor(Math.random()*4)],
        }));
        s.nebula = Array(5).fill(0).map(() => ({
          x: Math.random()*W, y: Math.random()*H,
          r: 100+Math.random()*200,
          color: ["#a78bfa","#00e5ff","#ff3b5c","#00ff88"][Math.floor(Math.random()*4)],
          alpha: 0.02+Math.random()*0.03,
        }));
      }

      else if (theme === "radar") {
        s.angle = 0;
        s.cx = W/2; s.cy = H/2;  // true center
        s.maxR = Math.min(W,H) * 0.44;
        s.blips = Array(8).fill(0).map(() => ({
          angle: Math.random()*Math.PI*2,
          dist: 60+Math.random()*s.maxR*0.75,
          life: Math.random(),
          color: Math.random()>0.25 ? "#00ff88" : "#ff3b5c",
          size: 2+Math.random()*3,
        }));
        s.rings = [0.25, 0.5, 0.75, 1.0];
        s.gridLines = 12;
        s.trails = [];
      }
    }

    function draw() {
      if (theme === "none") {
        ctx.clearRect(0,0,W,H);
        animRef.current = requestAnimationFrame(draw);
        return;
      }

      // ── Pulse Grid ────────────────────────────────────────
      if (theme === "pulse") {
        ctx.fillStyle="rgba(3,7,18,0.08)"; ctx.fillRect(0,0,W,H);
        const {cx,cy} = s;

        // Expanding rings
        s.rings.forEach(ring => {
          ring.r += ring.speed;
          if (ring.r > ring.maxR) ring.r = 0;
          const a = ring.alpha * (1 - ring.r/ring.maxR);
          ctx.beginPath(); ctx.arc(cx,cy,ring.r,0,Math.PI*2);
          ctx.strokeStyle = ring.color + Math.floor(a*120).toString(16).padStart(2,"0");
          ctx.lineWidth = 1; ctx.stroke();
        });

        // Grid lines from center
        for(let i=0;i<12;i++){
          const a = (i/12)*Math.PI*2;
          const grad = ctx.createLinearGradient(cx,cy,
            cx+Math.cos(a)*s.rings[0].maxR,
            cy+Math.sin(a)*s.rings[0].maxR);
          grad.addColorStop(0,"rgba(0,229,255,0.12)");
          grad.addColorStop(1,"rgba(0,229,255,0)");
          ctx.beginPath(); ctx.moveTo(cx,cy);
          ctx.lineTo(cx+Math.cos(a)*s.rings[0].maxR,
                     cy+Math.sin(a)*s.rings[0].maxR);
          ctx.strokeStyle=grad; ctx.lineWidth=0.5; ctx.stroke();
        }

        // Orbit nodes
        s.nodes.forEach(n => {
          n.pulse+=0.025;
          const nx = cx + Math.cos(n.angle)*n.dist;
          const ny = cy + Math.sin(n.angle)*n.dist;
          n.angle += 0.003;
          const glow = (Math.sin(n.pulse)+1)/2;
          ctx.beginPath(); ctx.arc(nx,ny,3+glow*2,0,Math.PI*2);
          ctx.fillStyle=n.color+Math.floor((0.4+glow*0.4)*255).toString(16).padStart(2,"0");
          ctx.fill();
          ctx.beginPath(); ctx.arc(nx,ny,8+glow*4,0,Math.PI*2);
          ctx.fillStyle=n.color+"15"; ctx.fill();
        });

        // Center pulse
        const t = Date.now()/1000;
        [20,35,50].forEach((r,i) => {
          const a = Math.sin(t*2+i)*0.3+0.1;
          ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2);
          ctx.strokeStyle=`rgba(0,229,255,${a})`;
          ctx.lineWidth=1.5; ctx.stroke();
        });
        ctx.beginPath(); ctx.arc(cx,cy,5,0,Math.PI*2);
        ctx.fillStyle="#00e5ff"; ctx.fill();
      }

      // ── Threat Map ────────────────────────────────────────
      else if (theme === "threatmap") {
        ctx.fillStyle="rgba(3,7,18,0.09)"; ctx.fillRect(0,0,W,H);

        // Generate connections periodically
        s.conTimer++;
        if(s.conTimer>45 && s.nodes.length>1){
          const src=s.nodes[Math.floor(Math.random()*s.nodes.length)];
          const tgt=s.nodes[Math.floor(Math.random()*s.nodes.length)];
          if(src!==tgt){
            s.connections.push({
              sx:src.x,sy:src.y,tx:tgt.x,ty:tgt.y,
              t:0,color:src.color,speed:0.015+Math.random()*0.01
            });
            // Packet animation
            s.packets.push({sx:src.x,sy:src.y,tx:tgt.x,ty:tgt.y,
              t:0,color:src.color,speed:0.02+Math.random()*0.015});
          }
          s.conTimer=0;
        }

        // Draw persistent connections (faded)
        s.connections.slice(-20).forEach(c=>{
          ctx.beginPath(); ctx.moveTo(c.sx,c.sy); ctx.lineTo(c.tx,c.ty);
          ctx.strokeStyle=c.color+"15"; ctx.lineWidth=0.5; ctx.stroke();
        });

        // Animate packets
        s.packets = s.packets.filter(p=>{
          p.t+=p.speed;
          if(p.t>=1) return false;
          const px=p.sx+(p.tx-p.sx)*p.t;
          const py=p.sy+(p.ty-p.sy)*p.t;
          ctx.beginPath(); ctx.arc(px,py,2.5,0,Math.PI*2);
          ctx.fillStyle=p.color; ctx.fill();
          ctx.beginPath(); ctx.arc(px,py,6,0,Math.PI*2);
          ctx.fillStyle=p.color+"30"; ctx.fill();
          return true;
        });

        // Draw nodes
        s.nodes.forEach(n=>{
          n.pulse+=n.pSpeed;
          const glow=(Math.sin(n.pulse)+1)/2;
          // Glow ring
          ctx.beginPath(); ctx.arc(n.x,n.y,n.r*4+glow*6,0,Math.PI*2);
          ctx.fillStyle=n.color+"10"; ctx.fill();
          // Node
          ctx.beginPath(); ctx.arc(n.x,n.y,n.r+glow,0,Math.PI*2);
          ctx.fillStyle=n.color+Math.floor((0.5+glow*0.4)*255).toString(16).padStart(2,"0");
          ctx.fill();
          // Crosshair for red nodes
          if(n.color==="#ff3b5c"){
            ctx.strokeStyle=n.color+"50"; ctx.lineWidth=0.5;
            ctx.beginPath();ctx.moveTo(n.x-12,n.y);ctx.lineTo(n.x+12,n.y);ctx.stroke();
            ctx.beginPath();ctx.moveTo(n.x,n.y-12);ctx.lineTo(n.x,n.y+12);ctx.stroke();
            ctx.beginPath();ctx.arc(n.x,n.y,8,0,Math.PI*2);ctx.stroke();
          }
        });
      }

      // ── Binary Stream ─────────────────────────────────────
      else if (theme === "binary") {
        ctx.fillStyle="rgba(3,7,18,0.07)"; ctx.fillRect(0,0,W,H);
        ctx.font="12px 'JetBrains Mono', monospace";
        s.drops.forEach((drop,i)=>{
          const bit = Math.random()>0.5 ? "1" : "0";
          ctx.fillStyle=drop.color+Math.floor(drop.alpha*180).toString(16).padStart(2,"0");
          ctx.fillText(bit, i*20, drop.y);
          drop.y += drop.speed;
          if(drop.y>H){
            drop.y=0;
            drop.alpha=0.2+Math.random()*0.4;
            drop.color=Math.random()>0.5 ? "#7c3aed" : "#a78bfa";
          }
        });
      }

      // ── Neural Network ────────────────────────────────────
      else if (theme === "neural") {
        ctx.fillStyle = "rgba(3,7,18,0.08)";
        ctx.fillRect(0,0,W,H);

        // Signal animations
        s.sigTimer++;
        if (s.sigTimer > 60 && s.nodes.length > 1) {
          const src = s.nodes[Math.floor(Math.random()*s.nodes.length)];
          const tgt = s.nodes[Math.floor(Math.random()*s.nodes.length)];
          if (src !== tgt) {
            s.signals.push({ sx:src.x, sy:src.y, tx:tgt.x, ty:tgt.y, t:0, color:src.color });
          }
          s.sigTimer = 0;
        }

        // Draw connections
        s.nodes.forEach((n,i) => {
          s.nodes.slice(i+1).forEach(m => {
            if (Math.abs(n.layer-m.layer) <= 1) {
              const dx=n.x-m.x, dy=n.y-m.y, d=Math.sqrt(dx*dx+dy*dy);
              if (d < 160) {
                ctx.beginPath(); ctx.moveTo(n.x,n.y); ctx.lineTo(m.x,m.y);
                ctx.strokeStyle = `rgba(167,139,250,${(1-d/160)*0.2})`;
                ctx.lineWidth = 0.6; ctx.stroke();
              }
            }
          });
        });

        // Draw signals
        s.signals = s.signals.filter(sig => {
          sig.t += 0.025;
          if (sig.t >= 1) return false;
          const px = sig.sx + (sig.tx-sig.sx)*sig.t;
          const py = sig.sy + (sig.ty-sig.sy)*sig.t;
          ctx.beginPath(); ctx.arc(px,py,3,0,Math.PI*2);
          ctx.fillStyle = sig.color; ctx.fill();
          // Glow
          ctx.beginPath(); ctx.arc(px,py,8,0,Math.PI*2);
          ctx.fillStyle = sig.color+"30"; ctx.fill();
          return true;
        });

        // Draw nodes
        s.nodes.forEach(n => {
          n.x+=n.vx; n.y+=n.vy; n.pulse+=n.pSpeed;
          if(n.x<20||n.x>W-20) n.vx*=-1;
          if(n.y<20||n.y>H-20) n.vy*=-1;
          const pulse = Math.sin(n.pulse)*0.5+0.5;
          // Outer glow
          ctx.beginPath(); ctx.arc(n.x,n.y,n.r*3+pulse*4,0,Math.PI*2);
          ctx.fillStyle=n.color+"12"; ctx.fill();
          // Inner
          ctx.beginPath(); ctx.arc(n.x,n.y,n.r+pulse*1.5,0,Math.PI*2);
          ctx.fillStyle=n.color+"80"; ctx.fill();
          // Core
          ctx.beginPath(); ctx.arc(n.x,n.y,n.r*0.5,0,Math.PI*2);
          ctx.fillStyle=n.color; ctx.fill();
        });
      }

      // ── Threat Storm ──────────────────────────────────────
      else if (theme === "storm") {
        s.flashAlpha = Math.max(0, s.flashAlpha-0.05);
        ctx.fillStyle = `rgba(3,7,18,${0.12+s.flashAlpha*0.2})`;
        ctx.fillRect(0,0,W,H);

        s.particles.forEach(p => {
          // Trail
          p.trail.push({x:p.x, y:p.y});
          if (p.trail.length > 8) p.trail.shift();
          p.trail.forEach((pt,i) => {
            ctx.beginPath(); ctx.arc(pt.x,pt.y,p.r*(i/p.trail.length),0,Math.PI*2);
            ctx.fillStyle=p.color+Math.floor((i/p.trail.length)*40).toString(16).padStart(2,"0");
            ctx.fill();
          });
          p.x+=p.vx; p.y+=p.vy;
          if(p.x<0)p.x=W; if(p.x>W)p.x=0;
          if(p.y<-10){p.y=H+10;p.x=Math.random()*W;p.trail=[];}
          ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
          ctx.fillStyle=p.color+"80"; ctx.fill();
        });

        // Lightning
        s.ltTimer++;
        if(s.ltTimer>100+Math.random()*180){
          s.flashAlpha = 0.3;
          const drawLightning = (x1,y1,x2,y2,depth) => {
            if(depth<=0){ctx.beginPath();ctx.moveTo(x1,y1);ctx.lineTo(x2,y2);ctx.stroke();return;}
            const mx=(x1+x2)/2+(Math.random()-0.5)*60;
            const my=(y1+y2)/2+(Math.random()-0.5)*30;
            drawLightning(x1,y1,mx,my,depth-1);
            drawLightning(mx,my,x2,y2,depth-1);
          };
          ctx.strokeStyle="rgba(255,100,100,0.7)"; ctx.lineWidth=1.5;
          drawLightning(Math.random()*W,0,Math.random()*W,H*0.5,4);
          s.ltTimer=0;
        }
      }



      // ── Deep Space / Starfield ────────────────────────────
      else if (theme === "starfield") {
        ctx.fillStyle="rgba(3,7,18,0.15)"; ctx.fillRect(0,0,W,H);

        // Nebula clouds
        s.nebula.forEach(n => {
          const grad = ctx.createRadialGradient(n.x,n.y,0,n.x,n.y,n.r);
          grad.addColorStop(0, n.color+Math.floor(n.alpha*255*3).toString(16).padStart(2,"0"));
          grad.addColorStop(1, n.color+"00");
          ctx.beginPath(); ctx.arc(n.x,n.y,n.r,0,Math.PI*2);
          ctx.fillStyle=grad; ctx.fill();
        });

        // Stars with warp effect
        const cx2=W/2, cy2=H/2;
        s.stars.forEach(star => {
          star.pz = star.z;
          star.z -= 2.5;
          if (star.z <= 0) {
            star.x = Math.random()*W; star.y=Math.random()*H;
            star.z = W; star.pz = star.z;
          }
          const sx = (star.x-cx2)*(W/star.z)+cx2;
          const sy = (star.y-cy2)*(W/star.z)+cy2;
          const px = (star.x-cx2)*(W/star.pz)+cx2;
          const py = (star.y-cy2)*(W/star.pz)+cy2;
          const size = Math.max(0.5, (1-star.z/W)*3);
          const alpha = Math.min(1, (1-star.z/W)*1.5);

          ctx.beginPath(); ctx.moveTo(px,py); ctx.lineTo(sx,sy);
          ctx.strokeStyle = star.color+Math.floor(alpha*200).toString(16).padStart(2,"0");
          ctx.lineWidth = size; ctx.stroke();
        });
      }

      // ── Mission Control Radar ─────────────────────────────
      else if (theme === "radar") {
        ctx.fillStyle="rgba(3,7,18,0.12)"; ctx.fillRect(0,0,W,H);
        const {cx,cy,maxR}=s;

        // Outer glow
        const outerGrad = ctx.createRadialGradient(cx,cy,maxR*0.7,cx,cy,maxR*1.1);
        outerGrad.addColorStop(0,"rgba(0,255,136,0)");
        outerGrad.addColorStop(1,"rgba(0,255,136,0.03)");
        ctx.beginPath(); ctx.arc(cx,cy,maxR*1.1,0,Math.PI*2);
        ctx.fillStyle=outerGrad; ctx.fill();

        // Grid lines (spokes)
        for(let i=0;i<s.gridLines;i++){
          const a = (i/s.gridLines)*Math.PI*2;
          ctx.beginPath(); ctx.moveTo(cx,cy);
          ctx.lineTo(cx+Math.cos(a)*maxR, cy+Math.sin(a)*maxR);
          ctx.strokeStyle="rgba(0,255,136,0.06)"; ctx.lineWidth=1; ctx.stroke();
        }

        // Rings
        s.rings.forEach((r,i) => {
          ctx.beginPath(); ctx.arc(cx,cy,maxR*r,0,Math.PI*2);
          ctx.strokeStyle=`rgba(0,255,136,${0.06+i*0.02})`; ctx.lineWidth=1; ctx.stroke();
          // Ring labels
          ctx.fillStyle="rgba(0,255,136,0.3)";
          ctx.font="10px 'JetBrains Mono', monospace";
          ctx.fillText(`${Math.round(r*100)}%`, cx+4, cy-maxR*r+12);
        });

        // Cross hairs
        ctx.strokeStyle="rgba(0,255,136,0.08)";
        ctx.beginPath();ctx.moveTo(cx-maxR,cy);ctx.lineTo(cx+maxR,cy);ctx.stroke();
        ctx.beginPath();ctx.moveTo(cx,cy-maxR);ctx.lineTo(cx,cy+maxR);ctx.stroke();

        // Sweep gradient
        s.angle+=0.012;
        for(let i=0;i<40;i++){
          const a=s.angle-(i*0.045);
          const alpha=(1-i/40)*0.10;
          ctx.beginPath(); ctx.moveTo(cx,cy);
          ctx.arc(cx,cy,maxR,a,a+0.045); ctx.closePath();
          ctx.fillStyle=`rgba(0,255,136,${alpha*0.7})`; ctx.fill();
        }

        // Sweep line
        ctx.beginPath(); ctx.moveTo(cx,cy);
        ctx.lineTo(cx+Math.cos(s.angle)*maxR, cy+Math.sin(s.angle)*maxR);
        ctx.strokeStyle="rgba(0,255,136,0.6)"; ctx.lineWidth=1.5; ctx.stroke();

        // Center dot
        ctx.beginPath(); ctx.arc(cx,cy,4,0,Math.PI*2);
        ctx.fillStyle="#00ff88"; ctx.fill();
        ctx.beginPath(); ctx.arc(cx,cy,12,0,Math.PI*2);
        ctx.fillStyle="rgba(0,255,136,0.2)"; ctx.fill();

        // Blips
        s.blips.forEach(b => {
          b.life+=0.006; if(b.life>1)b.life=0;
          const bx=cx+Math.cos(b.angle)*b.dist;
          const by=cy+Math.sin(b.angle)*b.dist;
          const a=Math.sin(b.life*Math.PI);
          const hex=Math.floor(a*255).toString(16).padStart(2,"0");

          // Check if sweep just passed this blip
          const angleDiff = ((b.angle - s.angle) % (Math.PI*2) + Math.PI*2) % (Math.PI*2);
          if (angleDiff < 0.3) b.life = 0.1;

          // Blip glow rings
          [12,8,4].forEach((r,i) => {
            ctx.beginPath(); ctx.arc(bx,by,r,0,Math.PI*2);
            ctx.fillStyle=b.color+Math.floor(a*(40-i*12)).toString(16).padStart(2,"0");
            ctx.fill();
          });
          // Blip core
          ctx.beginPath(); ctx.arc(bx,by,b.size,0,Math.PI*2);
          ctx.fillStyle=b.color+hex; ctx.fill();

          // Target crosshair for red blips
          if(b.color==="#ff3b5c"){
            ctx.strokeStyle=b.color+hex;
            ctx.lineWidth=0.8;
            ctx.beginPath();ctx.moveTo(bx-8,by);ctx.lineTo(bx+8,by);ctx.stroke();
            ctx.beginPath();ctx.moveTo(bx,by-8);ctx.lineTo(bx,by+8);ctx.stroke();
            ctx.beginPath();ctx.arc(bx,by,6,0,Math.PI*2);ctx.stroke();
          }
        });

        // Corner decorations
        const corners=[
          [20,20],[W-20,20],[20,H-20],[W-20,H-20]
        ];
        corners.forEach(([cx2,cy2]) => {
          ctx.strokeStyle="rgba(0,255,136,0.15)"; ctx.lineWidth=1;
          const size=20;
          ctx.beginPath();
          ctx.moveTo(cx2,cy2+size);ctx.lineTo(cx2,cy2);ctx.lineTo(cx2+size,cy2);
          ctx.stroke();
        });

        // HUD text
        ctx.fillStyle="rgba(0,255,136,0.25)";
        ctx.font="10px 'JetBrains Mono', monospace";
        ctx.fillText("AIPET X SOC", 30, H-30);
        ctx.fillText(`SCAN: ${new Date().toLocaleTimeString()}`, W-160, H-30);
        ctx.fillText("STATUS: MONITORING", 30, H-15);
        ctx.fillText(`THREATS: ${s.blips.filter(b=>b.color==="#ff3b5c").length}`, W-160, H-15);
      }

      animRef.current = requestAnimationFrame(draw);
    }

    init();
    ctx.fillStyle="#030712"; ctx.fillRect(0,0,W,H);
    if (theme !== "none") draw();

    return () => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener("resize", onResize);
    };
  }, [theme]);

  const currentTheme = THEMES.find(t => t.id === theme) || THEMES[0];

  return (
    <>
      <canvas ref={canvasRef}
        style={{ position:"fixed", top:0, left:0,
          width:"100vw", height:"100vh",
          zIndex:0, pointerEvents:"none", opacity:0.15 }} />

      <div style={{ position:"fixed", bottom:"80px", right:"16px",
        zIndex:9999, display:"flex", flexDirection:"column",
        alignItems:"flex-end", gap:"8px" }}>

        {open && (
          <div style={{ background:"rgba(8,12,16,0.97)",
            border:"1px solid #1e2a3a",
            borderRadius:"16px", padding:"10px",
            backdropFilter:"blur(24px)",
            boxShadow:"0 8px 40px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.03)",
            minWidth:"200px" }}>
            <div style={{ fontSize:"10px", color:"#475569",
              fontWeight:"700", textTransform:"uppercase",
              letterSpacing:"2px", padding:"4px 8px 10px",
              fontFamily:"'JetBrains Mono', monospace" }}>
              ⬡ Background Theme
            </div>
            {THEMES.map(t => (
              <button key={t.id} onClick={() => selectTheme(t.id)}
                style={{ display:"flex", alignItems:"center",
                  gap:"10px", width:"100%", padding:"9px 10px",
                  borderRadius:"10px", border:"none",
                  background: theme===t.id
                    ? t.color+"18" : "transparent",
                  cursor:"pointer", fontSize:"13px",
                  color: theme===t.id ? t.color : "#64748b",
                  fontWeight: theme===t.id ? "700" : "400",
                  textAlign:"left", transition:"all 0.15s",
                  fontFamily:"'Inter', sans-serif" }}>
                <span style={{ fontSize:"16px", minWidth:"20px" }}>
                  {t.icon}
                </span>
                <span style={{ flex:1 }}>{t.label}</span>
                {theme===t.id && (
                  <span style={{ display:"flex", alignItems:"center",
                    gap:"4px" }}>
                    <span style={{ width:"5px", height:"5px",
                      borderRadius:"50%", background:t.color,
                      boxShadow:`0 0 8px ${t.color}` }} />
                  </span>
                )}
              </button>
            ))}
          </div>
        )}

        <button onClick={() => setOpen(!open)}
          style={{ display:"flex", alignItems:"center", gap:"8px",
            padding:"10px 20px", borderRadius:"100px",
            border:`1px solid ${open ? currentTheme.color+"80" : currentTheme.color+"35"}`,
            background:"rgba(8,12,16,0.9)",
            backdropFilter:"blur(24px)",
            cursor:"pointer", fontSize:"13px", fontWeight:"700",
            color: currentTheme.color,
            boxShadow: open
              ? `0 0 24px ${currentTheme.color}25, 0 4px 20px rgba(0,0,0,0.5)`
              : "0 4px 20px rgba(0,0,0,0.4)",
            transition:"all 0.25s",
            fontFamily:"'Inter', sans-serif",
            letterSpacing:"0.3px" }}>
          <span style={{ fontSize:"15px" }}>{currentTheme.icon}</span>
          <span>{currentTheme.label}</span>
          <span style={{ fontSize:"9px", opacity:0.5,
            marginLeft:"2px" }}>{open ? "▲" : "▼"}</span>
        </button>
      </div>
    </>
  );
}

// Set body background to dark
document.body.style.backgroundColor = "#030712";
document.documentElement.style.backgroundColor = "#030712";

export default BackgroundSystem;
