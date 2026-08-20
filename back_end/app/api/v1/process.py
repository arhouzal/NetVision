from fastapi import APIRouter, HTTPException, status
import psutil

router = APIRouter(prefix="/process", tags=["Process"])

@router.delete("/{pid}", status_code=status.HTTP_200_OK)
def kill_process(pid: int):
    """
    Termine un processus par son PID (action initiée par l'administrateur de l'UI).
    """
    try:
        proc = psutil.Process(pid)
        proc.terminate()  # Envoie SIGTERM pour un arrêt propre
        # Si le processus résiste, on peut forcer (mais terminate() suffit généralement)
        return {"status": "success", "message": f"Processus {pid} ({proc.name()}) arrêté."}
    except psutil.NoSuchProcess:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Le processus avec le PID {pid} n'existe pas ou est déjà arrêté."
        )
    except psutil.AccessDenied:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permissions insuffisantes pour arrêter le processus {pid}."
        )
    except Exception as e:from fastapi import APIRouter, HTTPException, status
import psutil

router = APIRouter(prefix="/process", tags=["Process"])


@router.delete("/{pid}", status_code=status.HTTP_200_OK)
def kill_process(pid: int):
    """
    Termine un processus ET toute sa famille :
    - ses processus enfants (récursif)
    - tous les autres processus qui partagent le même chemin binaire
      (ex: toutes les instances Electron d'une même application, comme
      Obsidian qui relance automatiquement un sous-processus réseau tué seul).
    """
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc_path = proc.exe() if proc.exe() else None

        # 1. Récupère les enfants directs du processus ciblé (récursif)
        children = proc.children(recursive=True)

        # 2. Récupère tous les autres processus du système qui partagent
        #    le même chemin binaire (même famille d'application)
        siblings = []
        if proc_path:
            for p in psutil.process_iter(['pid', 'exe']):
                try:
                    if p.info['exe'] == proc_path and p.pid != pid:
                        siblings.append(psutil.Process(p.pid))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        # Liste complète et dédupliquée (par PID) à terminer
        all_procs = {p.pid: p for p in ([proc] + children + siblings)}.values()

        killed = []
        for p in all_procs:
            try:
                p.terminate()
                killed.append(p.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Attend 3s que les process se terminent proprement (SIGTERM)
        gone, alive = psutil.wait_procs(list(all_procs), timeout=3)

        # Ceux qui résistent -> on force avec SIGKILL
        for p in alive:
            try:
                p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {
            "status": "success",
            "message": f"Processus {pid} ({proc_name}) et {len(killed) - 1} processus lié(s) arrêté(s).",
            "killed_pids": killed
        }

    except psutil.NoSuchProcess:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Le processus avec le PID {pid} n'existe pas ou est déjà arrêté."
        )
    except psutil.AccessDenied:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permissions insuffisantes pour arrêter le processus {pid}."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'arrêt du processus : {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'arrêt du processus : {str(e)}"
        )
