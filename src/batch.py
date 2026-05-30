"""
Shared batch analysis loop for CLI and dashboard.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence

from src.analyzer import AnalysisResult, Analyzer
from src.postprocess import BatchContext
from src.progress import (
    PHASE_ERROR,
    PHASE_LOADING,
    PHASE_RUNNING,
    ProgressCallback,
    ProgressUpdate,
    format_progress_message,
)


def run_batch_analysis(
    functions: Sequence[dict[str, Any]],
    analyzer: Analyzer,
    *,
    run_id: str = "",
    on_progress: ProgressCallback | None = None,
    on_success: Callable[[AnalysisResult], None] | None = None,
    on_error: Callable[[dict[str, Any], Exception], None] | None = None,
) -> tuple[list[AnalysisResult], int, dict[str, str]]:
    """
    Analyze each function with the LLM, invoking optional callbacks.

    Returns:
        (results, error_count, decompiled_code_map)
    """
    total = len(functions)
    model = analyzer.model
    backend = analyzer.backend
    results: list[AnalysisResult] = []
    decompiled_code_map: dict[str, str] = {}
    errors = 0
    batch_context = BatchContext()

    if on_progress:
        on_progress(
            ProgressUpdate(
                phase=PHASE_LOADING,
                current=0,
                total=total,
                message=format_progress_message(PHASE_LOADING, "", model=model, backend=backend),
                model=model,
            )
        )

    for idx, fn in enumerate(functions, start=1):
        name = fn.get("functionName", fn.get("entry_point", "unknown"))
        ep = fn.get("entryPoint", "") or fn.get("entry_point", "")
        if ep:
            decompiled = fn.get("decompiledCode", "") or fn.get("decompiled_code", "")
            if decompiled:
                decompiled_code_map[ep] = decompiled

        completed_before = idx - 1

        def _progress_cb(update: ProgressUpdate) -> None:
            if on_progress:
                on_progress(
                    ProgressUpdate(
                        phase=update.phase,
                        current=idx,
                        total=total,
                        completed=completed_before,
                        function_name=update.function_name or name,
                        entry_point=update.entry_point or ep,
                        message=update.message,
                        errors=errors,
                        model=model,
                        last_error=update.last_error,
                    )
                )

        try:
            result = analyzer.analyze_function(
                fn,
                on_progress=_progress_cb,
                batch_context=batch_context,
                run_id=run_id,
            )
            results.append(result)
            if on_success:
                on_success(result)
        except Exception as exc:
            errors += 1
            err_msg = str(exc)[:200]
            if on_progress:
                on_progress(
                    ProgressUpdate(
                        phase=PHASE_ERROR,
                        current=idx,
                        total=total,
                        completed=idx,
                        function_name=name,
                        entry_point=ep,
                        message=f"Failed: {name} — {err_msg}",
                        errors=errors,
                        model=model,
                        last_error=err_msg,
                    )
                )
            if on_error:
                on_error(fn, exc)
        else:
            if on_progress:
                on_progress(
                    ProgressUpdate(
                        phase=PHASE_RUNNING,
                        current=idx,
                        total=total,
                        completed=idx,
                        function_name="",
                        entry_point="",
                        message=f"Completed {name} ({idx}/{total})",
                        errors=errors,
                        model=model,
                    )
                )

    return results, errors, decompiled_code_map
