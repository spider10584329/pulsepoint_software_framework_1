'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useMuiToast } from '@/components/ui/MuiToastProvider';
import Box from '@mui/material/Box';
import Container from '@mui/material/Container';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Link from '@mui/material/Link';
import Stack from '@mui/material/Stack';
import Paper from '@mui/material/Paper';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

function HomeContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { showToast } = useMuiToast();
  const [isLogin, setIsLogin] = useState(true);
  const [userRole, setUserRole] = useState<'admin' | 'agent'>('agent');
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    username: '',
    confirmPassword: '',
  });
  const [submitLoading, setSubmitLoading] = useState(false);
  const [hasShownError, setHasShownError] = useState(false);

  // Clear auth data on mount
  useEffect(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('userRole');
    document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    document.cookie = 'userRole=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
  }, []);

  useEffect(() => {
    if (hasShownError) return;

    if (searchParams.get('registered') === 'true') {
      showToast('success', 'Account Created!', 'Your account has been created successfully! Please sign in.');
      setIsLogin(true);
      setHasShownError(true);
      router.replace('/');
      return;
    }
    
    const errorParam = searchParams.get('error');
    if (errorParam) {
      if (errorParam === 'unauthorized') {
        showToast('warning', 'Authentication Required', 'You must be logged in to access that page.');
      } else if (errorParam === 'forbidden') {
        showToast('error', 'Access Denied', 'You do not have permission to access that page.');
      } else if (errorParam === 'invalid_token') {
        showToast('warning', 'Session Expired', 'Your session has expired. Please sign in again.');
      }
      setHasShownError(true);
      router.replace('/');
    }
  }, [searchParams]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleLoginClick = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitLoading(true);

    try {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          email: formData.email,
          password: formData.password,
          role: userRole,
        }),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Sign in failed');
      }

      if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        localStorage.setItem('userRole', userRole);
        
        showToast('success', 'Welcome Back!', `Successfully signed in as ${userRole}.`);

        const redirectPath = userRole === 'admin' ? '/admin' : '/agent';
        
        const checkCookiesAndRedirect = () => {
          const cookies = document.cookie;
          const hasToken = cookies.includes('token=');
          const hasRole = cookies.includes('userRole=');
          
          if (hasToken && hasRole) {
            window.location.href = redirectPath;
          } else {
            window.location.href = redirectPath;
          }
        };
        
        setTimeout(checkCookiesAndRedirect, 1500);
      } else {
        throw new Error('No token received');
      }
    } catch (err: any) {
      showToast('error', 'Sign In Failed', err.message || 'Something went wrong. Please try again.');
    } finally {
      setSubmitLoading(false);
    }
  };

  const handleRegisterClick = async (e: React.FormEvent) => {
    e.preventDefault();

    if (formData.password !== formData.confirmPassword) {
      showToast('error', 'Password Mismatch', 'Passwords do not match. Please try again.');
      return;
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(formData.password)) {
      showToast('error', 'Weak Password', 'Password must be at least 8 characters with uppercase, lowercase, and number.');
      return;
    }

    setSubmitLoading(true);

    try {
      const adminCheckResponse = await fetch('https://api.pulsepoint.clinotag.com/api/user/allusers', {
        method: 'GET',
        headers: {
          'Authorization': 'Basic ' + btoa('admin:admin'),
          'Content-Type': 'application/json',
        },
      });

      if (!adminCheckResponse.ok) {
        throw new Error('Failed to verify administrator email');
      }

      const adminData = await adminCheckResponse.json();
      const allUsers = adminData?.data || adminData || [];
      
      const adminUser = allUsers.find((user: { email?: string; id: number }) => 
        user.email?.toLowerCase() === formData.email.toLowerCase()
      );
      
      if (!adminUser) {
        showToast('error', 'Email Not Found', 'Administrator email does not exist in PulsePoint system.');
        setSubmitLoading(false);
        return;
      }

      const customerId = adminUser.id;

      const usernameCheckResponse = await fetch('/api/check-username', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: formData.username,
        }),
      });

      const usernameCheck = await usernameCheckResponse.json();
      
      if (usernameCheck.exists) {
        showToast('error', 'Username Taken', 'Account already exists with this username. Please choose another.');
        setSubmitLoading(false);
        return;
      }

      const response = await fetch('/api/register-user', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          adminEmail: formData.email,
          username: formData.username,
          password: formData.password,
          customerId,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Registration failed');
      }

      if (data.success) {
        showToast('success', 'Registration Successful!', 'Account pending approval. Please sign in.');
        setIsLogin(true);
        setFormData({
          email: '',
          password: '',
          username: '',
          confirmPassword: '',
        });
      } else {
        throw new Error(data.message || 'Registration failed');
      }
    } catch (err: any) {
      console.error('Registration error:', err);
      showToast('error', 'Registration Failed', err.message || 'Failed to register. Please try again.');
    } finally {
      setSubmitLoading(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        bgcolor: '#b1bcd4',
        p: 2,
      }}
    >
      <Container maxWidth="lg">
        <Card
          elevation={8}
          sx={{
            overflow: 'hidden',
            borderRadius: 2,
          }}
        >
          <Box
            sx={{
              display: 'flex',
              flexDirection: { xs: 'column', md: 'row' },
              minHeight: { xs: 'auto', md: 600 },
            }}
          >
            {/* Image Section */}
            <Box
              sx={{
                width: { xs: '100%', md: '40%' },
                bgcolor: 'secondary.main',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                p: 4,
              }}
            >
              <Box
                component="img"
                src="/sharecells-logo.png"
                alt="ShareCells Logo"
                sx={{
                  width: '100%',
                  maxWidth: { xs: 300, md: '100%' },
                  height: 'auto',
                  objectFit: 'contain',
                }}
              />
            </Box>

            {/* Form Section */}
            <Box
              sx={{
                width: { xs: '100%', md: '60%' },
                p: { xs: 3, sm: 4, md: 6 },
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
              }}
            >
              <Box sx={{ maxWidth: 450, mx: 'auto', width: '100%' }}>
                {/* Header */}
                <Typography
                  variant="h3"
                  component="h1"
                  align="center"
                  gutterBottom
                  sx={{ mb: 3, fontWeight: 600 }}
                >
                  {isLogin ? 'Sign in to Your Account' : 'Create Your Account'}
                </Typography>

                {/* Role Selection - Only on Sign In */}
                {isLogin && (
                  <Box sx={{ mb: 4 }}>
                    
                    <Stack 
                      direction="row" 
                      spacing={1.5} 
                      sx={{ 
                        justifyContent: 'center',
                        px: { xs: 1, sm: 0 }
                      }}
                    >
                      {/* Admin Card */}
                      <Paper
                        elevation={userRole === 'admin' ? 8 : 1}
                        onClick={() => setUserRole('admin')}
                        sx={{
                          flex: 1,
                          maxWidth: 120,
                          py: 0.75,
                          px: 2,
                          cursor: 'pointer',
                          transition: 'all 0.3s ease-in-out',
                          border: '1px solid',
                          borderRadius: '24px',
                          borderColor: userRole === 'admin' ? 'primary.main' : 'transparent',
                          bgcolor: userRole === 'admin' ? 'primary.main' : 'background.paper',
                          color: userRole === 'admin' ? 'primary.contrastText' : 'text.primary',
                          position: 'relative',
                          overflow: 'visible',
                          '&:hover': {
                            transform: 'translateY(-2px)',
                            boxShadow: 4,
                            borderColor: userRole === 'admin' ? 'primary.dark' : 'primary.light',
                          },
                        }}
                      >
                        <Box sx={{ position: 'relative' }}>
                          
                          <Typography 
                            variant="body2" 
                            fontWeight={600}
                            sx={{ 
                              color: 'inherit',
                              textAlign: 'center',
                              fontSize: '0.9rem'
                            }}
                          >
                            Admin
                          </Typography>
                        </Box>
                      </Paper>

                      {/* Agent Card */}
                      <Paper
                        elevation={userRole === 'agent' ? 8 : 1}
                        onClick={() => setUserRole('agent')}
                        sx={{
                          flex: 1,
                          maxWidth: 120,
                          py: 0.75,
                          px: 2,
                          cursor: 'pointer',
                          transition: 'all 0.3s ease-in-out',
                          border: '1px solid',
                          borderRadius: '24px',
                          borderColor: userRole === 'agent' ? 'primary.main' : 'transparent',
                          bgcolor: userRole === 'agent' ? 'primary.main' : 'background.paper',
                          color: userRole === 'agent' ? 'primary.contrastText' : 'text.primary',
                          position: 'relative',
                          overflow: 'visible',
                          '&:hover': {
                            transform: 'translateY(-2px)',
                            boxShadow: 4,
                            borderColor: userRole === 'agent' ? 'primary.dark' : 'primary.light',
                          },
                        }}
                      >
                        <Box sx={{ position: 'relative' }}>
                          
                          <Typography 
                            variant="body2" 
                            fontWeight={600}
                            sx={{ 
                              color: 'inherit',
                              textAlign: 'center',
                              fontSize: '0.9rem'
                            }}
                          >
                            Agent
                          </Typography>
                        </Box>
                      </Paper>
                    </Stack>
                    
                    {/* Info message for admin */}
                    {userRole === 'admin' && (
                      <Box 
                        sx={{ 
                          mt: 1, 
                          p: 0.5, 
                          bgcolor: 'info.lighter' || 'rgba(68, 68, 70, 0.08)',
                          borderRadius: 1,
                          
                        }}
                      >
                        <Typography 
                          variant="caption" 
                          sx={{ 
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 0.5,
                            fontSize: '0.75rem',
                            color: '#444'
                          }}
                        >
                          Admin accounts require a PulsePoint email address
                        </Typography>
                      </Box>
                    )}
                  </Box>
                )}

                {/* Forms */}
                <Box
                  component="form"
                  onSubmit={isLogin ? handleLoginClick : handleRegisterClick}
                  noValidate
                >
                  {isLogin ? (
                    // Login Form
                    <Stack spacing={2}>
                      <TextField
                        fullWidth
                        label={userRole === 'admin' ? 'Manager Email' : 'Username'}
                        name="email"
                        type="email"
                        value={formData.email}
                        onChange={handleChange}
                        required
                        autoComplete="email"
                        size="small"
                      />

                      <TextField
                        fullWidth
                        label="Password"
                        name="password"
                        type="password"
                        value={formData.password}
                        onChange={handleChange}
                        required
                        autoComplete="current-password"
                        size="small"
                      />

                      <Button
                        type="submit"
                        fullWidth
                        variant="contained"
                        size="large"
                        disabled={submitLoading}
                        sx={{ mt: 2 }}
                      >
                        {submitLoading ? (
                          <CircularProgress size={24} color="inherit" />
                        ) : (
                          'Sign In'
                        )}
                      </Button>
                    </Stack>
                  ) : (
                    // Registration Form
                    <Stack spacing={2.5}>
                      <TextField
                        fullWidth
                        label="Manager Email *"
                        name="email"
                        type="email"
                        value={formData.email}
                        onChange={handleChange}
                        required
                        size="small"
                      />

                      <TextField
                        fullWidth
                        label="Username *"
                        name="username"
                        value={formData.username}
                        onChange={handleChange}
                        required
                        size="small"
                      />

                      <TextField
                        fullWidth
                        label="Password *"
                        name="password"
                        type="password"
                        value={formData.password}
                        onChange={handleChange}
                        required
                        helperText="Min 8 characters with uppercase, lowercase, and number"
                        size="small"
                      />

                      <TextField
                        fullWidth
                        label="Confirm Password *"
                        name="confirmPassword"
                        type="password"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        required
                        size="small"
                      />

                      <Button
                        type="submit"
                        fullWidth
                        variant="contained"
                        size="large"
                        disabled={submitLoading}
                        sx={{ mt: 1 }}
                      >
                        {submitLoading ? (
                          <CircularProgress size={24} color="inherit" />
                        ) : (
                          'Create Account'
                        )}
                      </Button>
                    </Stack>
                  )}

                  {/* Toggle Link */}
                  <Box sx={{ mt: 2, textAlign: 'center' }}>
                    <Typography variant="body2" color="text.secondary">
                      {isLogin ? "Don't have an account? " : "Already have an account? "}
                      <Link
                        component="button"
                        type="button"
                        variant="body2"
                        onClick={() => setIsLogin(!isLogin)}
                        sx={{
                          fontWeight: 600,
                          cursor: 'pointer',
                          textDecoration: 'none',
                          '&:hover': {
                            textDecoration: 'underline',
                          },
                        }}
                      >
                        {isLogin ? 'Register' : 'Sign in here'}
                      </Link>
                    </Typography>
                  </Box>
                </Box>
              </Box>
            </Box>
          </Box>
        </Card>
      </Container>
    </Box>
  );
}

export default function Home() {
  return (
    <Suspense
      fallback={
        <Box
          sx={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            bgcolor: '#b1bcd4',
          }}
        >
          <CircularProgress size={48} />
        </Box>
      }
    >
      <HomeContent />
    </Suspense>
  );
}
