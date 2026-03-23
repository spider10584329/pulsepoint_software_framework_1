'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Avatar from '@mui/material/Avatar';
import Stack from '@mui/material/Stack';
import Chip from '@mui/material/Chip';
import DashboardIcon from '@mui/icons-material/Dashboard';
import PeopleIcon from '@mui/icons-material/People';
import AssignmentIcon from '@mui/icons-material/Assignment';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';

// Helper function to decode JWT token
function decodeToken(token: string) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Error decoding token:', error);
    return null;
  }
}

export default function AdminPage() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [adminId, setAdminId] = useState<number | null>(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');

    const decodedToken = decodeToken(token || '');
    if (decodedToken) {
      setAdminId(decodedToken.userId);
    }

    if (userData) {
      setUser(JSON.parse(userData));
    }
  }, [router]);

  const statsCards = [
    {
      title: 'Total Users',
      value: '0',
      icon: <PeopleIcon />,
      color: '#3b82f6',
      bgColor: '#dbeafe',
    },
    {
      title: 'Active Tasks',
      value: '0',
      icon: <AssignmentIcon />,
      color: '#f59e0b',
      bgColor: '#fef3c7',
    },
    {
      title: 'Completed',
      value: '0',
      icon: <TrendingUpIcon />,
      color: '#10b981',
      bgColor: '#d1fae5',
    },
  ];

  return (
    <Box>
      <Typography variant="h4" fontWeight={700} gutterBottom sx={{ mb: 3 }}>
        Dashboard
      </Typography>
    
      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {statsCards.map((stat, index) => (
          <Grid item xs={12} sm={6} md={4} key={index}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={2}>
                  <Box
                    sx={{
                      width: 56,
                      height: 56,
                      borderRadius: 2,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      bgcolor: stat.bgColor,
                      color: stat.color,
                    }}
                  >
                    {stat.icon}
                  </Box>
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      {stat.title}
                    </Typography>
                    <Typography variant="h4" fontWeight={700}>
                      {stat.value}
                    </Typography>
                  </Box>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Recent Activity */}
      <Card>
        <CardContent>
          <Typography variant="h6" fontWeight={600} gutterBottom>
            Recent Activity
          </Typography>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              minHeight: 200,
            }}
          >
            <Typography variant="body1" color="text.secondary">
              No recent activity to display
            </Typography>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}
