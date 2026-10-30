"""Analyse des journaux d'un pare-feu : nettoyage, résultats, figures.

Usage : python analyse.py
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # pas d'affichage : on enregistre seulement les PNG
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "logs_reseau.csv"
FIG_DIR = ROOT / "figures"
FIG_DIR.mkdir(exist_ok=True)


def nettoyer(df: pd.DataFrame) -> pd.DataFrame:
    """1) doublons exacts, 2) protocol en majuscules, 3) bytes_sent -> médiane."""
    df = df.drop_duplicates().copy()
    df["protocol"] = df["protocol"].str.upper()
    mediane = df["bytes_sent"].median()  # calculée APRÈS suppression des doublons
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    return df


def calculer_resultats(df: pd.DataFrame) -> dict:
    ports_par_ip = df.groupby("src_ip")["dst_port"].nunique()
    octets_par_ip = df.groupby("src_ip")["bytes_sent"].sum()
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(ports_par_ip.idxmax()),
        "ip_exfiltration": str(octets_par_ip.idxmax()),
    }


def sauver(fig, nom: str) -> None:
    fig.tight_layout()
    fig.savefig(FIG_DIR / nom, dpi=120)
    plt.close(fig)


def faire_figures(df: pd.DataFrame, res: dict) -> None:
    # 1. Top 10 des ports de destination
    fig, ax = plt.subplots(figsize=(8, 4.5))
    top = df["dst_port"].value_counts().head(10)
    ax.bar(top.index.astype(str), top.values, color="steelblue")
    ax.set(title="Top 10 des ports de destination", xlabel="Port de destination",
           ylabel="Nombre de connexions")
    sauver(fig, "01_top_ports.png")

    # 2. Connexions par heure
    fig, ax = plt.subplots(figsize=(8, 4.5))
    par_heure = pd.to_datetime(df["timestamp"]).dt.hour.value_counts().sort_index()
    ax.bar(par_heure.index, par_heure.values, color="darkorange")
    ax.set(title="Connexions par heure de la journée", xlabel="Heure (0-23)",
           ylabel="Nombre de connexions")
    ax.set_xticks(range(0, 24, 2))
    sauver(fig, "02_connexions_par_heure.png")

    # 3. Volume d'octets par type d'appareil
    fig, ax = plt.subplots(figsize=(8, 4.5))
    vol = df.groupby("device_type")["bytes_sent"].sum().sort_values() / 1e6
    ax.barh(vol.index, vol.values, color="seagreen")
    ax.set(title="Volume d'octets envoyés par type d'appareil",
           xlabel="Octets envoyés (Mo)", ylabel="Type d'appareil")
    sauver(fig, "03_octets_par_appareil.png")

    # 4. Répartition ALLOW / DENY
    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    rep = df["action"].value_counts()
    ax.pie(rep.values, labels=rep.index, autopct="%1.1f%%",
           colors=["#4c9f70" if a == "ALLOW" else "#d9534f" for a in rep.index])
    ax.set_title("Répartition ALLOW / DENY")
    sauver(fig, "04_allow_deny.png")

    # 5. Nombre de ports distincts par IP source (détection du scan)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ports = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    couleurs = ["#d9534f" if ip == res["ip_scanner"] else "steelblue" for ip in ports.index]
    ax.bar(ports.index, ports.values, color=couleurs)
    ax.set(title="Ports distincts contactés par IP source (top 10)",
           xlabel="IP source", ylabel="Nombre de ports distincts")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    sauver(fig, "05_ports_distincts_par_ip.png")

    # 6. Octets envoyés par IP source (détection de l'exfiltration)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    octets = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10) / 1e6
    couleurs = ["#d9534f" if ip == res["ip_exfiltration"] else "steelblue" for ip in octets.index]
    ax.bar(octets.index, octets.values, color=couleurs)
    ax.set(title="Total d'octets envoyés par IP source (top 10)",
           xlabel="IP source", ylabel="Octets envoyés (Mo)")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    sauver(fig, "06_octets_par_ip.png")


def main() -> None:
    df = nettoyer(pd.read_csv(DATA))
    res = calculer_resultats(df)
    (ROOT / "resultats.json").write_text(json.dumps(res, indent=2, ensure_ascii=False) + "\n")
    faire_figures(df, res)
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
