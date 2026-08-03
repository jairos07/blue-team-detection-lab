# Blue Team Detection Lab

> Lab de detección Blue Team desplegado sobre Proxmox VE — simulación de ataques reales contra Active Directory y documentación de su detección con Zeek, Suricata y Wazuh SIEM, mapeados al framework MITRE ATT&CK.

![Zeek](https://img.shields.io/badge/Zeek-NDR-2980B9?logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-8.0.5-EF3B2D?logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-4.9.2-5C4EE5?logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows_Server-2022-0078D4?logo=windows&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Attacker-Kali_Linux-367BF0?logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![Proxmox](https://img.shields.io/badge/Proxmox-VE-E57000?logo=proxmox&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?logoColor=white)

---

## ¿Qué es esto?

Este lab implementa un ciclo completo de **detección Blue Team** contra un entorno Active Directory real. Va más allá de documentar ataques — demuestra la capacidad de detectarlos con un stack de seguridad real: análisis de tráfico de red con Zeek, detección por firmas con Suricata y visibilidad de endpoint con Wazuh.

Cada escenario está mapeado al framework MITRE ATT&CK, incluye la ejecución real del ataque desde Kali Linux, y documenta exactamente qué capturó cada herramienta de detección — logs reales, alertas reales y capturas de pantalla del momento de la detección.

El enfoque es **infraestructura y configuración**, no programación. Todo el stack — port mirroring, reglas custom, integración de herramientas — está desplegado y documentado desde cero.

---

## Topología de red

```
                    ┌─────────────────────────────────────────────────────────────────┐
                    │                        Proxmox VE Host                           │
                    │                   Red interna: 192.168.100.0/24                  │
                    │                       Bridge: vmbr1                              │
                    │                                                                   │
                    │  ┌──────────────┐  ┌───────────────────┐  ┌──────────────────┐  │
                    │  │   pfSense    │  │   ubuntu-server   │  │      wazuh       │  │
                    │  │   Firewall   │  │   DHCP + DNS      │  │   SIEM + EDR     │  │
                    │  │ 192.168.     │  │   192.168.100.1   │  │  192.168.100.113 │  │
                    │  │   100.2      │  │   Agente Wazuh    │  │  Tailscale VPN   │  │
                    │  └──────────────┘  └───────────────────┘  └──────────────────┘  │
                    │                                                                   │
                    │  ┌─────────────────────────┐  ┌────────────────────────────────┐ │
                    │  │   windows-server        │  │        ndr-sensor              │ │
                    │  │   Windows Server 2022   │  │   Suricata 8.0.5 + Zeek       │ │
                    │  │   Active Directory DC   │  │   Grafana + Loki + Promtail   │ │
                    │  │   192.168.100.3         │  │   192.168.100.4               │ │
                    │  │   Dominio: red.local    │  │   Port mirror: vmbr1          │ │
                    │  └─────────────────────────┘  └────────────────────────────────┘ │
                    │                                                                   │
                    │  ┌──────────────┐                                                 │
                    │  │    Kali      │                                                 │
                    │  │   Atacante   │                                                 │
                    │  │ 192.168.     │                                                 │
                    │  │   100.16     │                                                 │
                    │  └──────────────┘                                                 │
                    └───────────────────────────────────────────────────────────────────┘
```

| VM | Sistema operativo | Rol | IP |
|---|---|---|---|
| `pfSense` | pfSense CE 2.7.2 | Firewall perimetral / gateway | 192.168.100.2 |
| `ubuntu-server` | Ubuntu Server 24.04 LTS | DHCP + DNS + Agente Wazuh | 192.168.100.1 |
| `windows-server` | Windows Server 2022 | Domain Controller — red.local | 192.168.100.3 |
| `ndr-sensor` | Ubuntu Server 24.04 LTS | Suricata + Zeek + Grafana/Loki | 192.168.100.4 |
| `wazuh` | Ubuntu Server 24.04 LTS | SIEM — stack Wazuh vía Docker | 192.168.100.113 |
| `kali` | Kali Linux | Máquina atacante | 192.168.100.16 |

---

## Stack de detección

| Herramienta | Versión | Propósito |
|---|---|---|
| Zeek | Latest (Docker) | Análisis de protocolo de red — conn.log, dns.log, kerberos.log, smb_files.log, http.log |
| Suricata | 8.0.5 | Detección por firmas — ET Open + reglas custom por escenario |
| Wazuh | 4.9.2 | Visibilidad de endpoint — Event IDs de Windows en el DC |
| Grafana + Loki + Promtail | Latest | Visualización centralizada de logs de Zeek y Suricata |
| Proxmox tc mirror | — | Port mirroring de vmbr1 hacia el sensor NDR |

---

## Escenarios ejecutados

| ID | Técnica MITRE | Descripción | Detección | Estado |
|---|---|---|---|---|
| [S01](escenarios/S01-reconocimiento/) | T1046 — Network Service Discovery | Reconocimiento de red con Nmap | Zeek conn.log + Suricata ET SCAN | ✅ Completado |
| [S02](escenarios/S02-brute-force-ad/) | T1110.001 — Password Guessing | Brute force AD con netexec | Wazuh Event ID 4625 (77 hits) | ✅ Completado |
| [S03](escenarios/S03-kerberoasting/) | T1558.003 — Kerberoasting | Solicitud TGS con impacket-GetUserSPNs | Zeek kerberos.log cipher rc4-hmac | ✅ Completado |
| [S04](escenarios/S04-lateral-movement-smb/) | T1021.002 — SMB/Windows Admin Shares | Movimiento lateral vía SMB | Zeek smb_files.log + Suricata | 🔄 Pendiente |
| [S05](escenarios/S05-c2-beaconing/) | T1071.001 — Web Protocols | C2 beaconing sobre HTTP | Zeek http.log + Suricata | 🔄 Pendiente |

---

## Resumen de detecciones

### S01 — Reconocimiento de red (T1046)

| Herramienta | Evidencia | Indicador |
|---|---|---|
| Suricata | Alertas ET SCAN + LAB-S01 (SID 9000102) | Alto volumen SYN desde 192.168.100.16 |
| Zeek | conn.log — conexiones en estado S0/REJ | > 1000 puertos escaneados en < 30s |

### S02 — Brute Force AD (T1110.001)

| Herramienta | Evidencia | Indicador |
|---|---|---|
| Wazuh | 77 × Event ID 4625 en 15 minutos | Pico visible en Security Events del DC |
| Zeek | conn.log — ráfaga de conexiones a puerto 445 | Cadencia regular no humana desde misma IP |

### S03 — Kerberoasting (T1558.003)

| Herramienta | Evidencia | Indicador |
|---|---|---|
| Zeek | kerberos.log — `cipher: rc4-hmac` | TGS solicitado para svc-sql con cifrado RC4 |
| Kali | Hash TGS `$krb5tgs$23$*svc-sql$RED.LOCAL$...` | Ticket obtenido para cracking offline |

---

## Reglas custom desplegadas

### Suricata — `/var/lib/suricata/rules/custom.rules`

| SID | Escenario | Descripción |
|---|---|---|
| 9000101 | S01 | Escaneo SYN desde red externa — alto volumen |
| 9000102 | S01 | Escaneo SYN desde red interna — host comprometido |
| 9000103 | S01 | Nmap NSE User-Agent detectado en HTTP |
| 9000404 | S04 | Alto volumen conexiones SMB internas |
| 9000501 | S05 | C2 beaconing HTTP — peticiones periódicas |
| 9000503 | S05 | Consulta DNS a dominio C2 con typosquatting |

### Wazuh — `local_rules_lab.xml`

| Rule ID | Escenario | Descripción |
|---|---|---|
| 100201 | S02 | Múltiples fallos Kerberos (Event 4771) — nivel 12 |
| 100202 | S02 | Múltiples fallos de logon (Event 4625) — nivel 12 |
| 100203 | S02 | Cuenta de dominio bloqueada (Event 4740) — nivel 14 |
| 100300 | S03 | TGS con cifrado RC4 (Event 4769, tipo 0x17) — nivel 5 |
| 100301 | S03 | Múltiples TGS RC4 en < 10s — Kerberoasting confirmado — nivel 14 |

---

## Infraestructura de captura

El sensor NDR (`ndr-sensor`) captura el tráfico de toda la red mediante **port mirroring a nivel de hipervisor** con `tc` en Proxmox. El tráfico de cada VM se espeja hacia `tap305i2`, que corresponde a la interfaz `ens20` del sensor en modo promiscuo.

```bash
# Mirror activo en pve1 — servicios systemd
ndr-mirror.service  →  fwpr100p0 (Kali) → tap305i2 (ndr-sensor ens20)
                        fwpr302p0 (DC)   → tap305i2 (ndr-sensor ens20)
                        fwpr302p1 (DC)   → tap305i2 (ndr-sensor ens20)
```

> El tráfico unicast entre VMs no es visible en el bridge directamente — el mirror debe apuntar a los **firewall bridge ports** (`fwpr<vmid>p<nic>`) de cada VM, no a `vmbr1`.

---

## Habilidades demostradas

- **Detección de red (NDR)** — despliegue y configuración de Zeek y Suricata sobre tráfico real de red
- **SIEM** — configuración de Wazuh, reglas custom correlacionadas con Event IDs de Windows AD
- **MITRE ATT&CK** — mapeo de técnicas ofensivas a controles de detección defensivos
- **Port mirroring en Proxmox** — configuración de `tc` para captura de tráfico entre VMs
- **Reglas Suricata** — desarrollo de reglas IDS custom por escenario con SIDs propios
- **Active Directory** — comprensión de Kerberos, SPNs, Event IDs de seguridad de Windows
- **Docker Compose** — despliegue y gestión del stack NDR y Wazuh
- **Análisis de logs** — correlación de evidencias entre Zeek, Suricata y Wazuh
- **Grafana + Loki** — visualización centralizada de logs de seguridad en tiempo real
- **Tailscale** — acceso remoto seguro al stack de detección

---

## Estructura del repositorio

```
blue-team-detection-lab/
├── README.md
├── escenarios/
│   ├── S01-reconocimiento/          # T1046 — Nmap + Suricata + Zeek
│   ├── S02-brute-force-ad/          # T1110.001 — netexec + Wazuh
│   ├── S03-kerberoasting/           # T1558.003 — impacket + Zeek kerberos.log
│   ├── S04-lateral-movement-smb/   # T1021.002 — pendiente
│   └── S05-c2-beaconing/           # T1071.001 — pendiente
├── reglas/
│   ├── suricata/                    # Reglas .rules custom por escenario
│   └── wazuh/                       # Reglas XML custom para Wazuh
├── playbooks/                       # Playbooks de respuesta por técnica
├── navigator/                       # Layer ATT&CK Navigator (JSON)
├── infraestructura/                 # Documentación del entorno y port mirroring
└── docs/                            # Guías de despliegue del stack de detección
```

---

## Aviso legal

Este es un **entorno de laboratorio aislado** ejecutándose en un host Proxmox VE privado. Ningún servicio está expuesto a internet. Todas las direcciones IP, nombres de dominio y credenciales que aparecen en la documentación pertenecen únicamente a la red interna del lab y no tienen exposición externa. Este proyecto tiene fines educativos y de portfolio.