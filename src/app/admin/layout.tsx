'use client';

import { useEffect, useState, ReactNode } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useMuiToast } from '@/components/ui/MuiToastProvider';
import Box from '@mui/material/Box';
import Drawer from '@mui/material/Drawer';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Avatar from '@mui/material/Avatar';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Divider from '@mui/material/Divider';
import MenuIcon from '@mui/icons-material/Menu';
import DashboardIcon from '@mui/icons-material/Dashboard';
import PeopleIcon from '@mui/icons-material/People';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import LogoutIcon from '@mui/icons-material/Logout';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import { useTheme } from '@mui/material/styles';
import useMediaQuery from '@mui/material/useMediaQuery';

const DRAWER_WIDTH_EXPANDED = 240;
const DRAWER_WIDTH_COLLAPSED = 64;

interface MenuItem {
  id: string;
  label: string;
  path: string;
  icon: ReactNode;
}

const menuItems: MenuItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    path: '/admin',
    icon: <DashboardIcon />,
  },
  {
    id: 'users',
    label: 'Users',
    path: '/admin/users',
    icon: <PeopleIcon />,
  },
];

export default function AdminLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { showToast } = useMuiToast();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const dropdownOpen = Boolean(anchorEl);

  useEffect(() => {
    if (isMobile) {
      setSidebarOpen(false);
    } else {
      setSidebarOpen(true);
    }
  }, [isMobile]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const userRole = localStorage.getItem('userRole');
    const userData = localStorage.getItem('user');

    if (!token || userRole !== 'admin') {
      router.push('/?error=unauthorized');
      return;
    }

    if (userData) {
      setUser(JSON.parse(userData));
    }
    setLoading(false);
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('userRole');
    document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    document.cookie = 'userRole=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    showToast('info', 'Logged Out', 'You have been successfully logged out.');
    setTimeout(() => {
      router.push('/');
    }, 500);
  };

  const handleDrawerToggle = () => {
    if (isMobile) {
      setMobileOpen(!mobileOpen);
    } else {
      setSidebarOpen(!sidebarOpen);
    }
  };

  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  if (loading) {
    return (
      <Box
        sx={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          bgcolor: 'background.default',
        }}
      >
        <Box textAlign="center">
          <CircularProgress size={48} />
          <Typography variant="body1" sx={{ mt: 2 }} color="text.secondary">
            Loading...
          </Typography>
        </Box>
      </Box>
    );
  }

  const drawerContent = (
    <>
      {/* Logo Section */}
      <Box
        sx={{
          height: 72,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          bgcolor: 'secondary.main',
          borderBottom: 1,
          borderColor: 'divider',
        }}
      >
        <Box
          component="img"
          src={sidebarOpen || isMobile ? "/sharecells-logo.png" : "/sharecells-square.png"}
          alt="ShareCells Logo"
          sx={{
            height: 56,
            width: 'auto',
            transition: 'all 0.3s',
          }}
        />
      </Box>

      {/* Navigation Menu */}
      <List sx={{ px: isMobile || sidebarOpen ? 2 : 1, py: 2 }}>
        {menuItems.map((item) => (
          <ListItem key={item.id} disablePadding sx={{ mb: 1 }}>
            <ListItemButton
              selected={pathname === item.path}
              onClick={() => {
                router.push(item.path);
                if (isMobile) {
                  setMobileOpen(false);
                }
              }}
              sx={{
                borderRadius: 50,
                justifyContent: sidebarOpen || isMobile ? 'flex-start' : 'center',
                px: isMobile || sidebarOpen ? 2 : 1,
                py: 0.75,
                minHeight: 'auto',
                '&.Mui-selected': {
                  bgcolor: 'grey.100',
                  borderColor: 'grey.400',
                  borderWidth: 1,
                  borderStyle: 'solid',
                  '&:hover': {
                    bgcolor: 'grey.200',
                  },
                },
              }}
            >
              <ListItemIcon
                sx={{
                  minWidth: sidebarOpen || isMobile ? 40 : 0,
                  color: pathname === item.path ? 'primary.main' : 'text.secondary',
                  justifyContent: 'center',
                }}
              >
                {item.icon}
              </ListItemIcon>
              {(sidebarOpen || isMobile) && (
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{
                    fontSize: '0.775rem',
                    fontWeight: pathname === item.path ? 600 : 400,
                  }}
                />
              )}
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </>
  );

  const drawerWidth = sidebarOpen ? DRAWER_WIDTH_EXPANDED : DRAWER_WIDTH_COLLAPSED;

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
      {/* App Bar */}
      <AppBar
        position="fixed"
        elevation={1}
        sx={{
          width: { md: `calc(100% - ${drawerWidth}px)` },
          ml: { md: `${drawerWidth}px` },
          bgcolor: 'background.paper',
          color: 'text.primary',
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="toggle drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>

          <Box sx={{ flexGrow: 1 }} />

          {/* User Menu */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <IconButton
              onClick={handleMenuClick}
              size="small"
              disableRipple
              sx={{
                p: 0.5,
                '&:hover': {
                  bgcolor: 'transparent',
                },
              }}
            >
              <AccountCircleIcon 
                sx={{
                  fontSize: 32,
                  color: 'primary.main',
                  mr: 1,
                }}
              />
              <Typography variant="body2" fontWeight={500} sx={{ mr: 0.5 }}>
                Admin
              </Typography>
              <KeyboardArrowDownIcon
                sx={{
                  transform: dropdownOpen ? 'rotate(180deg)' : 'rotate(0)',
                  transition: 'transform 0.3s',
                }}
              />
            </IconButton>

            <Menu
              anchorEl={anchorEl}
              open={dropdownOpen}
              onClose={handleMenuClose}
              transformOrigin={{ horizontal: 'right', vertical: 'top' }}
              anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
              PaperProps={{
                sx: { mt: 1, minWidth: 180 },
              }}
            >
              <MenuItem onClick={handleLogout}>
                <ListItemIcon>
                  <LogoutIcon fontSize="small" />
                </ListItemIcon>
                <ListItemText>Logout</ListItemText>
              </MenuItem>
            </Menu>
          </Box>
        </Toolbar>
      </AppBar>

      {/* Sidebar - Mobile */}
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={handleDrawerToggle}
        ModalProps={{
          keepMounted: true,
        }}
        sx={{
          display: { xs: 'block', md: 'none' },
          '& .MuiDrawer-paper': {
            boxSizing: 'border-box',
            width: DRAWER_WIDTH_EXPANDED,
          },
        }}
      >
        {drawerContent}
      </Drawer>

      {/* Sidebar - Desktop */}
      <Drawer
        variant="permanent"
        sx={{
          display: { xs: 'none', md: 'block' },
          width: drawerWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
            overflowX: 'hidden',
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.sharp,
              duration: theme.transitions.duration.leavingScreen,
            }),
          },
        }}
        open={sidebarOpen}
      >
        {drawerContent}
      </Drawer>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { md: `calc(100% - ${drawerWidth}px)` },
          mt: 8,
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        {children}
      </Box>
    </Box>
  );
}
