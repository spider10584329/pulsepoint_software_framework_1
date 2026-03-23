'use client';

import { createContext, useContext, useState, ReactNode } from 'react';
import Snackbar from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Slide, { SlideProps } from '@mui/material/Slide';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

interface ToastMessage {
  id: string;
  type: ToastType;
  title: string;
  message: string;
  duration?: number;
}

interface ToastContextType {
  showToast: (type: ToastType, title: string, message: string, duration?: number) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

function SlideTransition(props: SlideProps) {
  return <Slide {...props} direction="left" />;
}

export function MuiToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [currentToast, setCurrentToast] = useState<ToastMessage | null>(null);

  const showToast = (type: ToastType, title: string, message: string, duration: number = 5000) => {
    const id = Math.random().toString(36).substring(7);
    const newToast: ToastMessage = {
      id,
      type,
      title,
      message,
      duration,
    };

    setToasts(prev => [...prev, newToast]);
    
    // Show the first toast immediately if none is currently showing
    if (!currentToast) {
      setCurrentToast(newToast);
    }
  };

  const handleClose = (_event?: React.SyntheticEvent | Event, reason?: string) => {
    if (reason === 'clickaway') {
      return;
    }
    
    setCurrentToast(null);
    
    // After closing, show next toast in queue
    setTimeout(() => {
      setToasts(prev => {
        const remaining = prev.filter(t => t.id !== currentToast?.id);
        if (remaining.length > 0) {
          setCurrentToast(remaining[0]);
        }
        return remaining;
      });
    }, 300);
  };

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <Snackbar
        open={!!currentToast}
        autoHideDuration={currentToast?.duration || 5000}
        onClose={handleClose}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        TransitionComponent={SlideTransition}
        sx={{ mt: 2, mr: 2 }}
      >
        {currentToast ? (
          <Alert
            onClose={handleClose}
            severity={currentToast.type}
            variant="filled"
            sx={{
              width: '100%',
              minWidth: '320px',
              maxWidth: '448px',
              boxShadow: 3,
            }}
          >
            <AlertTitle sx={{ fontWeight: 600 }}>{currentToast.title}</AlertTitle>
            {currentToast.message}
          </Alert>
        ) : undefined}
      </Snackbar>
    </ToastContext.Provider>
  );
}

export function useMuiToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useMuiToast must be used within a MuiToastProvider');
  }
  return context;
}
