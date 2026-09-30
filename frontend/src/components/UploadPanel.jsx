//frontend/src/components/UploadPanel.jsx

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getUploadConfig, uploadLogFile } from '../api/siem.js';

import Panel from "./ui/Panel";
import PanelHeader from "./ui/PanelHeader";
import StatusDot from "./ui/StatusDot";

const FALLBACK_MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const AUTO_SOURCE_BY_EXTENSION = {
  '.evtx': 'windows_evtx',
  '.json': 'json',
  '.ndjson': 'json',
  '.csv': 'csv',
};

export default function UploadPanel() {
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
      setError(uploadError.response?.data?.error || uploadError.message || 'Upload failed.');
    } finally {
      setIsUploading(false);
    }
  }

  return (
    <Panel className="flex flex-col">
      <PanelHeader
          icon="📂"
          title="Manual Log Upload"
          subtitle="Import logs into the SIEM engine"
          right={
              <StatusDot
                  color="bg-blue-500"
                  text={`Max ${formatBytes(maxUploadBytes)}`}
              />
          }
      />

      <div className="grid gap-6 p-6 lg:grid-cols-[250px_1fr]">
        <div className="rounded-lg border border-hairline bg-raised p-5">
          <label className="text-xs font-semibold uppercase tracking-widest text-ink-muted">
            Parser
          </label>
          <select
            value={sourceType}
            onChange={(event) => handleSourceTypeChange(event.target.value)}
            disabled={isLoading}
            className="mt-2 w-full rounded-lg border border-hairline bg-raised px-4 py-3 text-sm text-white transition focus:border-accent focus:outline-none"
          >
            {supportedTypes.map((type) => (
              <option key={type.id} value={type.id}>
                {type.label}
              </option>
            ))}
          </select>
          <p className="mt-2 text-xs text-ink-muted">
            {selectedType?.description || 'Loading parser configuration...'}
          </p>
          {selectedType && (
            <p className="mt-2 font-mono text-[11px] text-ink-dim">
              accepts: {selectedType.extensions.join(', ')}
            </p>
          )}
        </div>

        <div>
          <label
            onDragOver={(event) => {
              event.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(event) => {
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
            hover:scale-[1.01]
            ${
            dragActive
            ? "border-accent bg-accent/10"
            : "border-hairline bg-raised"
            }`}
          >
            <input
              type="file"
              accept={accept}
              className="hidden"
              onChange={(event) => handleFileSelection(event.target.files?.[0])}
            />

            <div className="mb-4 text-6xl">
            🗂️
            </div>

            <h3 className="max-w-full break-all text-center text-lg font-semibold text-white">
            {file ? file.name : "Drag & Drop Log Files"}
            </h3>

            <div className="mt-5 flex flex-wrap gap-2">
              {supportedTypes.map(type=>(
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
            <div className="mt-3 rounded-md border border-severity-critical/30 bg-severity-critical/10 px-3 py-2 text-sm text-severity-critical">
              {error}
            </div>
          )}

          {result && (
            <div className="mt-3 rounded-md border border-accent/30 bg-accent/10 px-3 py-3 text-sm text-ink-primary">
              <p>
                Indexed {result.indexedCount} event(s) from <span className="font-mono">{result.fileName}</span>
                {result.alertsTriggered ? ` and fired ${result.alertsTriggered} alert(s).` : '.'}
              </p>
              {result.skippedCount > 0 && (
                <p className="mt-1 text-xs text-ink-muted">Skipped {result.skippedCount} unrecognized record(s).</p>
              )}
              {result.warnings?.length > 0 && (
                <ul className="mt-2 space-y-1 text-xs text-ink-muted">
                  {result.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {(isUploading || progress.stage === 'done') && (
            <div className="mt-5 rounded-lg border border-hairline bg-raised p-4">
              <div className="mb-1 flex items-center justify-between font-mono text-[11px] text-ink-muted">
                <span>{progressLabel(progress.stage)}</span>
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
              disabled={isUploading || isLoading || !file || Boolean(error)}
              className="rounded-lg bg-accent px-5 py-2.5 font-semibold text-white transition hover:scale-105 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-40"
            >
              {isUploading ? 'uploading...' : 'upload and index'}
            </button>
            <button
              onClick={() => {
                setFile(null);
                setError('');
                setResult(null);
                setProgress({ percent: 0, stage: 'idle' });
              }}
              disabled={isUploading && !file}
              className="rounded-lg border border-hairline bg-raised px-5 py-2.5 text-sm font-medium text-white transition hover:border-accent hover:bg-accent/10"
            >
              clear
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
