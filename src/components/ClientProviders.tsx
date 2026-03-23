'use client';

import { AuthProvider } from "@/contexts/AuthContext";
import { MuiToastProvider } from "@/components/ui/MuiToastProvider";
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { theme } from "@/lib/theme";
import EmotionCacheProvider from "@/lib/emotionCache";

export default function ClientProviders({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <EmotionCacheProvider>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <MuiToastProvider>
          <AuthProvider>
            {children}
          </AuthProvider>
        </MuiToastProvider>
      </ThemeProvider>
    </EmotionCacheProvider>
  );
}
