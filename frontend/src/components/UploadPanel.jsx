import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getUploadConfig, uploadLogFile } from '../api/siem.js';
import { useAuth } from '../context/AuthContext.jsx';

import Panel from "./ui/Panel";
import PanelHeader from "./ui/PanelHeader";
import StatusDot from "./ui/StatusDot";
import {
  IconFolder,
  IconLock,
  IconUploadCloud,
  IconAlertTriangle,
  IconCheck,
  IconClose,
  IconZap,
} from './ui/Icons.jsx';

const FALLBACK_MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const AUTO_SOURCE_BY_EXTENSION = {
  '.evtx': 'windows_evtx',
  '.json': 'json',
  '.ndjson': 'json',
  '.csv': 'csv',
};

export default function UploadPanel() {
  const { hasRole } = useAuth();
  const canUpload = hasRole('admin', 'analyst');

  const queryClient = useQueryClient();
  const [sourceType, setSourceType] = useState('json');
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [progress, setProgress] = useState({ percent: 0, stage: 'idle' });
  const [isUploading, setIsUploading] = useState(false);

  const { data: uploadConfig, isLoading } = useQuery({
    queryKey: ['uploads', 'config'],
    queryFn: getUploadConfig,
    staleTime: Infinity,
  });

  const supportedTypes = uploadConfig?.supportedUploadTypes ?? [];
  const selectedType = supportedTypes.find((type) => type.id === sourceType) ?? null;
  const maxUploadBytes = uploadConfig?.maxUploadSizeBytes ?? FALLBACK_MAX_UPLOAD_BYTES;
  const accept = Array.from(
    new Set(supportedTypes.flatMap((type) => type.extensions))
  ).join(',');

  function handleSourceTypeChange(nextSourceType) {
    setSourceType(nextSourceType);
    setResult(null);

    if (!file) {
      setError('');
      return;
    }

    setError(validateFile(file, nextSourceType, uploadConfig));
  }

  function handleFileSelection(nextFile) {
    if (!nextFile) return;

    const inferredSourceType = inferSourceType(nextFile.name);
    const nextType = inferredSourceType || sourceType;

    if (inferredSourceType) {
      setSourceType(inferredSourceType);
    }

    setFile(nextFile);
    setResult(null);
    setProgress({ percent: 0, stage: 'idle' });
    setError(validateFile(nextFile, nextType, uploadConfig));
  }

  async function handleUpload() {
    if (!file) {
      setError('Choose a file before uploading.');
      return;
    }

    const validationError = validateFile(file, sourceType, uploadConfig);
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsUploading(true);
    setError('');
    setResult(null);

    try {
      const filePayload = await readFile(file, sourceType, (event) => {
        const ratio = event.total ? event.loaded / event.total : 0;
        setProgress({
          percent: Math.min(30, Math.round(ratio * 30)),
          stage: 'reading',
        });
      });

      setProgress({ percent: 35, stage: 'uploading' });

      const response = await uploadLogFile(
        {
          fileName: file.name,
          fileSize: file.size,
          sourceType,
          ...filePayload,
        },
        (event) => {
          const ratio = event.total ? event.loaded / event.total : 0;
          setProgress({
            percent: Math.max(35, Math.min(100, 35 + Math.round(ratio * 65))),
            stage: 'uploading',
          });
        }
      );

      setProgress({ percent: 100, stage: 'done' });
      setResult(response);

      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['logs'] }),
        queryClient.invalidateQueries({ queryKey: ['stats'] }),
        queryClient.invalidateQueries({ queryKey: ['alerts'] }),
      ]);
    } catch (uploadError) {
      setProgress({ percent: 0, stage: 'idle' });
      const rawMsg = uploadError.response?.data?.error || uploadError.message;
      const sanitized =
        typeof rawMsg === 'string' &&
        !rawMsg.includes('stack') &&
        !rawMsg.includes('at ') &&
        !rawMsg.includes('SyntaxError')
          ? rawMsg
          : 'Unable to process and index log file. Please check file format and encoding.';
      setError(sanitized);
    } finally {
      setIsUploading(false);
    }
  }

  return (
    <Panel className="flex flex-col">
      <PanelHeader
        icon={<IconFolder className="h-5 w-5" />}
        title="Manual Log Upload"
        subtitle="Import logs into the SIEM engine"
        right={
          <StatusDot
            color="bg-blue-500"
            text={`Max ${formatBytes(maxUploadBytes)}`}
          />
        }
      />

      <div className="grid gap-4 sm:gap-6 p-4 sm:p-6 lg:grid-cols-[250px_1fr]">
        <div className="rounded-lg border border-hairline bg-raised p-4 sm:p-5">
          <label className="text-xs font-semibold uppercase tracking-widest text-ink-muted">
            Parser
          </label>
          {isLoading ? (
            <div className="mt-2 space-y-2 animate-pulse">
              <div className="h-11 w-full rounded-lg bg-hairline/40" />
              <div className="h-3 w-3/4 rounded bg-hairline/25" />
            </div>
          ) : (
            <>
              <select
                value={sourceType}
                onChange={(event) => handleSourceTypeChange(event.target.value)}
                disabled={isUploading}
                aria-label="Select parser type"
                className="mt-2 w-full rounded-lg border border-hairline bg-raised px-4 py-3 text-sm text-white transition focus:border-accent focus:outline-none"
              >
                {supportedTypes.map((type) => (
                  <option key={type.id} value={type.id}>
                    {type.label}
                  </option>
                ))}
              </select>
              <p className="mt-2 text-xs text-ink-muted">
                {selectedType?.description || 'Parser configuration ready.'}
              </p>
              {selectedType && (
                <p className="mt-2 font-mono text-[11px] text-ink-dim">
                  accepts: {selectedType.extensions.join(', ')}
                </p>
              )}
            </>
          )}
        </div>

        <div>
          {!canUpload && (
            <div className="mb-4 rounded-lg border border-yellow-600/30 bg-yellow-950/20 px-4 py-2.5 text-xs text-yellow-300 flex items-center gap-2">
              <IconLock className="h-4 w-4 shrink-0 text-yellow-300" />
              <span>Log ingestion is restricted to Analysts and Administrators. Your current role has Read-Only permissions.</span>
            </div>
          )}

          <label
            onDragOver={(event) => {
              if (!canUpload) return;
              event.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => {
              if (!canUpload) return;
              setDragActive(false);
            }}
            onDrop={(event) => {
              if (!canUpload) return;
              event.preventDefault();
              setDragActive(false);
              handleFileSelection(event.dataTransfer.files?.[0]);
            }}
            className={`flex min-h-[260px]
            flex-col
            items-center
            justify-center
            rounded-panel
            border-2
            border-dashed
            transition-all
            duration-300
            ${!canUpload ? 'opacity-40 cursor-not-allowed border-hairline bg-raised' : 'hover:scale-[1.01] cursor-pointer'}
            ${
            dragActive && canUpload
            ? "border-accent bg-accent/10"
            : "border-hairline bg-raised"
            }`}
          >
            <input
              type="file"
              accept={accept}
              disabled={!canUpload}
              className="hidden"
              onChange={(event) => handleFileSelection(event.target.files?.[0])}
            />

            <div className="mb-4 text-accent">
              <IconUploadCloud className="h-16 w-16" />
            </div>

            <h3 className="max-w-full break-all text-center text-lg font-semibold text-white">
              {file ? file.name : "Drag & Drop Log Files"}
            </h3>

            <div className="mt-5 flex flex-wrap gap-2">
              {supportedTypes.map((type) => (
                <span key={type.id} className="rounded-full bg-orange-500/10 px-3 py-1 text-xs text-orange-400">
                  {type.label}
                </span>
              ))}
            </div>

            <p className="mt-2 text-sm text-ink-muted">
              {file ? `${formatBytes(file.size)} selected` : "or click to browse"}
            </p>
          </label>

          {error && (
            <div
              role="alert"
              aria-live="polite"
              className="mt-3 flex items-start gap-2.5 rounded-lg border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-sm text-severity-critical"
            >
              <IconAlertTriangle className="h-4 w-4 shrink-0 text-severity-critical mt-0.5" />
              <div className="flex-1 font-medium">{error}</div>
            </div>
          )}

          {result && (
            <div
              role="status"
              aria-live="polite"
              className="mt-3 rounded-lg border border-emerald-500/40 bg-emerald-950/20 p-4 text-sm text-emerald-300"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-semibold">
                  <IconCheck className="h-4 w-4 text-emerald-400" />
                  <span>
                    Successfully indexed {result.indexedCount} event(s) from{' '}
                    <span className="font-mono text-white">{result.fileName}</span>
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setResult(null)}
                  aria-label="Dismiss upload result"
                  className="text-xs text-emerald-400 hover:text-white"
                >
                  <IconClose className="h-3.5 w-3.5" />
                </button>
              </div>
              {result.alertsTriggered > 0 && (
                <p className="mt-1.5 font-mono text-xs text-orange-300 flex items-center gap-1.5">
                  <IconZap className="h-3.5 w-3.5 text-accent shrink-0" />
                  <span>Generated {result.alertsTriggered} new detection alert(s). Check the Alert Queue!</span>
                </p>
              )}
              {result.skippedCount > 0 && (
                <p className="mt-1 text-xs text-emerald-400/80">
                  Skipped {result.skippedCount} unrecognized record(s).
                </p>
              )}
              {result.warnings?.length > 0 && (
                <ul className="mt-2 space-y-1 text-xs text-emerald-400/70 border-t border-emerald-800/40 pt-2">
                  {result.warnings.map((warning, i) => (
                    <li key={i}>• {warning}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {(isUploading || progress.stage === 'done') && (
            <div className="mt-5 rounded-lg border border-hairline bg-raised p-4">
              <div className="mb-1 flex items-center justify-between font-mono text-[11px] text-ink-muted">
                <span className="capitalize">{progressLabel(progress.stage)}</span>
                <span>{progress.percent}%</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-void">
                <div
                  className="h-full bg-gradient-to-r from-orange-400 via-orange-500 to-orange-600 transition-all duration-200"
                  style={{ width: `${progress.percent}%` }}
                />
              </div>
            </div>
          )}

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              onClick={handleUpload}
              disabled={!canUpload || isUploading || isLoading || !file || Boolean(error)}
              aria-label="Upload and index log file"
              className="inline-flex items-center gap-2 rounded-lg bg-accent px-5 py-2.5 font-semibold text-white transition hover:scale-105 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:scale-100"
            >
              {isUploading ? (
                <>
                  <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  <span>Processing...</span>
                </>
              ) : (
                <span>Upload and Index</span>
              )}
            </button>
            <button
              onClick={() => {
                setFile(null);
                setError('');
                setResult(null);
                setProgress({ percent: 0, stage: 'idle' });
              }}
              disabled={isUploading}
              aria-label="Clear selected file"
              className="rounded-lg border border-hairline bg-raised px-5 py-2.5 text-sm font-medium text-white transition hover:border-accent hover:bg-accent/10 disabled:opacity-30"
            >
              Clear
            </button>
          </div>
        </div>
      </div>
    </Panel>
  );
}

function validateFile(file, sourceType, uploadConfig) {
  if (!file) return '';

  const supportedTypes = uploadConfig?.supportedUploadTypes ?? [];
  const selectedType = supportedTypes.find((type) => type.id === sourceType);
  const maxUploadBytes = uploadConfig?.maxUploadSizeBytes ?? FALLBACK_MAX_UPLOAD_BYTES;

  if (!selectedType) {
    return 'Select a parser before uploading.';
  }

  if (file.size > maxUploadBytes) {
    return `File exceeds the ${formatBytes(maxUploadBytes)} upload limit.`;
  }

  const extension = getFileExtension(file.name);
  if (!selectedType.extensions.includes(extension)) {
    return `${selectedType.label} expects ${selectedType.extensions.join(', ')} files.`;
  }

  return '';
}

function inferSourceType(fileName) {
  return AUTO_SOURCE_BY_EXTENSION[getFileExtension(fileName)] || '';
}

function getFileExtension(fileName) {
  const dotIndex = fileName.lastIndexOf('.');
  return dotIndex >= 0 ? fileName.slice(dotIndex).toLowerCase() : '';
}

function readFile(file, sourceType, onProgress) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onerror = () => reject(new Error('Failed to read the selected file.'));
    reader.onprogress = onProgress;

    reader.onload = () => {
      try {
        if (sourceType === 'windows_evtx') {
          resolve({
            encoding: 'base64',
            content: arrayBufferToBase64(reader.result),
          });
          return;
        }

        resolve({
          encoding: 'utf8',
          content: typeof reader.result === 'string' ? reader.result : '',
        });
      } catch (error) {
        reject(error);
      }
    };

    if (sourceType === 'windows_evtx') {
      reader.readAsArrayBuffer(file);
      return;
    }

    reader.readAsText(file);
  });
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = '';

  for (let index = 0; index < bytes.length; index += chunkSize) {
    const chunk = bytes.subarray(index, index + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

function progressLabel(stage) {
  switch (stage) {
    case 'reading':
      return 'reading file';
    case 'uploading':
      return 'uploading and indexing';
    case 'done':
      return 'complete';
    default:
      return 'ready';
  }
}
