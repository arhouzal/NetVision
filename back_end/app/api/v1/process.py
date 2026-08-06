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
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'arrêt du processus : {str(e)}"
        )
