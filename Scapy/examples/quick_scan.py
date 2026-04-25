#!/usr/bin/env python3
"""
Script rápido para escanear la red VMware VMnet8
"""

import sys
from pathlib import Path

# Agregar el directorio raíz al PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from scapy_framework.scanner.arp_scanner import ARPScanner

# Configuración
VMWARE_INTERFACE = 'VMware Network Adapter VMnet8'
NETWORK_RANGE = '192.168.16.0/24'

def main():
    print("\n[*] Escaneando red VMware VMnet8...")
    print(f"[*] Red: {NETWORK_RANGE}")
    print(f"[*] Interfaz: {VMWARE_INTERFACE}\n")

    try:
        # Crear scanner
        scanner = ARPScanner(interface=VMWARE_INTERFACE)

        # Escanear la red
        resultados = scanner.scan(NETWORK_RANGE, timeout=3)

        if resultados:
            print(f"[+] Se encontraron {len(resultados)} dispositivos:\n")
            print(f"{'IP Address':<20} {'MAC Address':<20} {'Vendor'}")
            print("-" * 70)

            for resultado in resultados:
                ip = resultado['ip']
                mac = resultado['mac']
                vendor = resultado.get('vendor', 'Unknown')

                # Identificar dispositivos conocidos
                if ip == '192.168.16.1':
                    tipo = "[HOST Windows]"
                elif ip == '192.168.16.37':
                    tipo = "[Kali VM]"
                elif ip.endswith('.2'):
                    tipo = "[Gateway probable]"
                else:
                    tipo = ""

                print(f"{ip:<20} {mac:<20} {vendor:<20} {tipo}")

            print()

            # Detectar gateway probable
            for resultado in resultados:
                if resultado['ip'].endswith('.2'):
                    print(f"[!] Gateway probable detectado: {resultado['ip']}")
                    break

        else:
            print("[-] No se encontraron dispositivos")
            print("[!] Verifica que:")
            print("    - Tus VMs estén encendidas")
            print("    - Estén en modo NAT (VMnet8)")
            print("    - Ejecutes PowerShell como Administrador")

    except PermissionError:
        print("\n[!] ERROR: Permisos insuficientes")
        print("[!] Ejecuta PowerShell como Administrador")

    except Exception as e:
        print(f"\n[!] Error al escanear: {e}")
        print(f"[!] Verifica que la interfaz '{VMWARE_INTERFACE}' existe")
        print(f"[!] Puedes verificarla con: ipconfig")

if __name__ == '__main__':
    main()
