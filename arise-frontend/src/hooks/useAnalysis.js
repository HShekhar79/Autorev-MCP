// arise-frontend/src/hooks/useAnalysis.js — FINAL AUTHORITATIVE VERSION
import { useState, useCallback } from 'react';
import { analyzeFile, MOCK_RESULT } from '../services/api';

const STAGES = ['extraction','behaviour','capability','mitre','risk','cvss','verdict'];

export function useAnalysis() {
  const [status,  setStatus]  = useState('idle');
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState(null);
  const [stage,   setStage]   = useState('');
  const [pct,     setPct]     = useState(0);
  const [taskId,  setTaskId]  = useState(null);

  const analyze = useCallback(async (file, demo = false) => {
    setStatus('uploading');
    setError(null);
    setResult(null);
    setStage('');
    setPct(0);
    setTaskId(null);

    try {
      if (demo) {
        setStatus('processing');
        for (let i = 0; i < STAGES.length; i++) {
          setStage(STAGES[i]);
          setPct(Math.round(((i + 1) / STAGES.length) * 90));
          await new Promise(r => setTimeout(r, 380));
        }
        setPct(100);
        await new Promise(r => setTimeout(r, 250));
        setResult(MOCK_RESULT);
        setTaskId('demo');
        setStatus('done');
      } else {
        setStatus('processing');
        const { result: data, taskId: tid } = await analyzeFile(file, (s, p) => {
          setStage(s);
          setPct(p);
        });
        setResult(data);
        setTaskId(tid);
        setStatus('done');
      }
    } catch (e) {
      setError(e.message);
      setStatus('error');
    }
  }, []);

  const reset = useCallback(() => {
    setStatus('idle');
    setResult(null);
    setError(null);
    setStage('');
    setPct(0);
    setTaskId(null);
  }, []);

  return { status, result, error, stage, pct, taskId, analyze, reset };
}
