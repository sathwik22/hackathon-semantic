import React, { useState, useEffect } from 'react';
import {
    Container,
    Typography,
    Card,
    CardContent,
    CardActions,
    Button,
    Collapse,
    Table,
    TableBody,
    TableRow,
    TableCell,
    Link,
    Chip,
    Box,
    ButtonGroup,
    Paper,
    TableHead,
    TableContainer,
    Select,
    MenuItem,
    FormControl,
    InputLabel,
    Grid,
    Divider,
    Badge,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import SecurityIcon from '@mui/icons-material/Security';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import BugReportIcon from '@mui/icons-material/BugReport';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import PriorityHighIcon from '@mui/icons-material/PriorityHigh';

// Import your JSON data
import trivyData from './trivy-report.json';
import grypeData from './grype-report.json';
import combinedData from './combined-report.json';

const getSeverityColor = (severity) => {
    severity = severity.toLowerCase();
    switch (severity) {
        case 'critical':
            return '#7B1FA2'; // Purple
        case 'high':
            return '#C62828'; // Red
        case 'medium':
            return '#EF6C00'; // Orange
        case 'low':
            return '#FFC107'; // Amber
        default:
            return '#78909C'; // Blue Grey
    }
};

const getSeverityIcon = (severity) => {
    severity = severity.toLowerCase();
    switch (severity) {
        case 'critical':
            return <ErrorIcon fontSize="small" />;
        case 'high':
            return <PriorityHighIcon fontSize="small" />;
        case 'medium':
            return <WarningIcon fontSize="small" />;
        case 'low':
            return <InfoIcon fontSize="small" />;
        default:
            return <InfoIcon fontSize="small" />;
    }
};

export default function VulnerabilityViewer() {
    const [expandedIndex, setExpandedIndex] = useState(null);
    const [filterSeverity, setFilterSeverity] = useState('ALL');
    const [currentData, setCurrentData] = useState(trivyData);
    const [dataSource, setDataSource] = useState('trivy');
    const [vulnerabilitiesToFix, setVulnerabilitiesToFix] = useState([]);
    const [sortBy, setSortBy] = useState('severity');

    // Extract vulnerabilities based on the data format
    const getVulnerabilities = (data, source) => {
        if (source === 'trivy') {
            return data.Results && data.Results[0]
                ? data.Results[0].Vulnerabilities || []
                : [];
        } else if (source === 'grype') {
            return data.matches || [];
        } else if (source === 'combined') {
            return data.vulnerabilities || [];
        }
        return [];
    };

    // Get key vulnerability properties based on data source
    const getVulnerabilityProps = (vuln, source) => {
        if (source === 'trivy') {
            return {
                id: vuln.VulnerabilityID,
                packageName: vuln.PkgName,
                packageVersion: vuln.InstalledVersion,
                severity: vuln.Severity,
                description: vuln.Description || vuln.Title,
                fixVersions: vuln.FixedVersion ? [vuln.FixedVersion] : [],
                references: vuln.References || [],
                dataSource: vuln.DataSource ? vuln.DataSource.Name : 'Unknown',
                cvss: vuln.CVSS,
            };
        } else if (source === 'grype') {
            return {
                id: vuln.vulnerability ? vuln.vulnerability.id : 'Unknown',
                packageName: vuln.artifact ? vuln.artifact.name : 'Unknown',
                packageVersion: vuln.artifact
                    ? vuln.artifact.version
                    : 'Unknown',
                severity: vuln.vulnerability
                    ? vuln.vulnerability.severity
                    : 'Unknown',
                description: vuln.vulnerability
                    ? vuln.vulnerability.description
                    : 'No description',
                fixVersions:
                    vuln.vulnerability && vuln.vulnerability.fix
                        ? vuln.vulnerability.fix.versions || []
                        : [],
                references: vuln.vulnerability
                    ? vuln.vulnerability.urls || []
                    : [],
                dataSource: vuln.vulnerability
                    ? vuln.vulnerability.dataSource
                    : 'Unknown',
                cvss: vuln.vulnerability ? vuln.vulnerability.cvss : null,
                risk: vuln.vulnerability ? vuln.vulnerability.risk : 0,
            };
        } else if (source === 'combined') {
            return {
                id: vuln.VulnerabilityID,
                packageName: vuln.PkgName,
                packageVersion: '',
                severity: vuln.severity,
                description: vuln.description,
                fixVersions: vuln.fix_versions || [],
                references: [],
                dataSource: 'Combined',
                cvss: null,
            };
        }
        return {};
    };

    // Get all vulnerabilities
    const results = getVulnerabilities(currentData, dataSource);

    // Filter results based on severity
    const filteredResults =
        filterSeverity === 'ALL'
            ? results
            : results.filter((vuln) => {
                  if (dataSource === 'trivy') {
                      return (
                          vuln.Severity &&
                          vuln.Severity.toUpperCase() === filterSeverity
                      );
                  } else if (dataSource === 'grype') {
                      return (
                          vuln.vulnerability &&
                          vuln.vulnerability.severity &&
                          vuln.vulnerability.severity.toUpperCase() ===
                              filterSeverity
                      );
                  } else if (dataSource === 'combined') {
                      return (
                          vuln.severity &&
                          vuln.severity.toUpperCase() === filterSeverity
                      );
                  }
                  return false;
              });

    // Sort results
    const sortedResults = [...filteredResults].sort((a, b) => {
        const getProperty = (item, prop) => {
            if (dataSource === 'trivy') {
                if (prop === 'severity') {
                    const severityOrder = {
                        CRITICAL: 4,
                        HIGH: 3,
                        MEDIUM: 2,
                        LOW: 1,
                        UNKNOWN: 0,
                    };
                    return severityOrder[item.Severity?.toUpperCase()] || 0;
                }
                return item[prop] || '';
            } else if (dataSource === 'grype') {
                if (prop === 'severity') {
                    const severityOrder = {
                        CRITICAL: 4,
                        HIGH: 3,
                        MEDIUM: 2,
                        LOW: 1,
                        UNKNOWN: 0,
                    };
                    return (
                        severityOrder[
                            item.vulnerability?.severity?.toUpperCase()
                        ] || 0
                    );
                } else if (prop === 'risk') {
                    return item.vulnerability?.risk || 0;
                }
                return (
                    item.vulnerability?.[prop] || item.artifact?.[prop] || ''
                );
            } else if (dataSource === 'combined') {
                if (prop === 'severity') {
                    const severityOrder = {
                        CRITICAL: 4,
                        HIGH: 3,
                        MEDIUM: 2,
                        LOW: 1,
                        UNKNOWN: 0,
                    };
                    return severityOrder[item.severity?.toUpperCase()] || 0;
                }
                return item[prop] || '';
            }
            return '';
        };

        const valueA = getProperty(a, sortBy);
        const valueB = getProperty(b, sortBy);

        if (sortBy === 'severity' || sortBy === 'risk') {
            return valueB - valueA; // Higher severity/risk first
        }

        // Default string comparison
        if (typeof valueA === 'string' && typeof valueB === 'string') {
            return valueA.localeCompare(valueB);
        }

        return 0;
    });

    // Group vulnerabilities by package
    const vulnerabilitiesByPackage = {};
    sortedResults.forEach((vuln) => {
        const props = getVulnerabilityProps(vuln, dataSource);
        const key = props.packageName;

        if (!vulnerabilitiesByPackage[key]) {
            vulnerabilitiesByPackage[key] = [];
        }
        vulnerabilitiesByPackage[key].push(vuln);
    });

    const toggleExpand = (index) => {
        setExpandedIndex(expandedIndex === index ? null : index);
    };

    const changeDataSource = (source) => {
        setDataSource(source);
        setExpandedIndex(null);

        if (source === 'trivy') {
            setCurrentData(trivyData);
        } else if (source === 'grype') {
            setCurrentData(grypeData);
        } else if (source === 'combined') {
            setCurrentData(combinedData);
        }
    };

    const countBySeverity = (severity) => {
        return results.filter((vuln) => {
            if (dataSource === 'trivy') {
                return (
                    vuln.Severity && vuln.Severity.toUpperCase() === severity
                );
            } else if (dataSource === 'grype') {
                return (
                    vuln.vulnerability &&
                    vuln.vulnerability.severity &&
                    vuln.vulnerability.severity.toUpperCase() === severity
                );
            } else if (dataSource === 'combined') {
                return (
                    vuln.severity && vuln.severity.toUpperCase() === severity
                );
            }
            return false;
        }).length;
    };

    const addToFixList = (vuln) => {
        const props = getVulnerabilityProps(vuln, dataSource);
        setVulnerabilitiesToFix([...vulnerabilitiesToFix, props]);
    };

    const removeFromFixList = (id) => {
        setVulnerabilitiesToFix(
            vulnerabilitiesToFix.filter((v) => v.id !== id)
        );
    };

    const isInFixList = (id) => {
        return vulnerabilitiesToFix.some((v) => v.id === id);
    };

    return (
        <Container maxWidth="lg" sx={{ py: 4 }}>
            <Typography
                variant="h3"
                gutterBottom
                sx={{
                    fontWeight: 600,
                    color: '#1a237e',
                    mb: 2,
                }}
            >
                Vulnerability Report
            </Typography>

            {/* Data source selection */}
            <Paper elevation={0} sx={{ mb: 4, p: 2, display: 'inline-block' }}>
                <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 500 }}>
                    Select Data Source:
                </Typography>
                <ButtonGroup
                    variant="contained"
                    size="large"
                    aria-label="data source selection"
                >
                    <Button
                        startIcon={<SecurityIcon />}
                        onClick={() => changeDataSource('trivy')}
                        color={dataSource === 'trivy' ? 'primary' : 'inherit'}
                        sx={{
                            fontWeight: 'bold',
                            bgcolor:
                                dataSource === 'trivy'
                                    ? undefined
                                    : 'rgba(0,0,0,0.05)',
                            color:
                                dataSource === 'trivy'
                                    ? undefined
                                    : 'text.primary',
                        }}
                    >
                        Trivy
                    </Button>
                    <Button
                        startIcon={<BugReportIcon />}
                        onClick={() => changeDataSource('grype')}
                        color={dataSource === 'grype' ? 'primary' : 'inherit'}
                        sx={{
                            fontWeight: 'bold',
                            bgcolor:
                                dataSource === 'grype'
                                    ? undefined
                                    : 'rgba(0,0,0,0.05)',
                            color:
                                dataSource === 'grype'
                                    ? undefined
                                    : 'text.primary',
                        }}
                    >
                        Grype
                    </Button>
                    <Button
                        startIcon={<CompareArrowsIcon />}
                        onClick={() => changeDataSource('combined')}
                        color={
                            dataSource === 'combined' ? 'primary' : 'inherit'
                        }
                        sx={{
                            fontWeight: 'bold',
                            bgcolor:
                                dataSource === 'combined'
                                    ? undefined
                                    : 'rgba(0,0,0,0.05)',
                            color:
                                dataSource === 'combined'
                                    ? undefined
                                    : 'text.primary',
                        }}
                    >
                        AI Combined
                    </Button>
                </ButtonGroup>
            </Paper>

            <Typography
                variant="subtitle1"
                color="text.secondary"
                sx={{ mb: 3, fontSize: '1.1rem' }}
            >
                Data Source: <strong>{dataSource.toUpperCase()}</strong>
                {dataSource === 'trivy' &&
                    currentData.CreatedAt &&
                    ` | Scanned at: ${new Date(
                        currentData.CreatedAt
                    ).toLocaleString()}`}
            </Typography>

            {/* Summary statistics */}
            <Box sx={{ mb: 4 }}>
                <Grid container spacing={2}>
                    <Grid item xs={12} md={3}>
                        <Paper
                            elevation={3}
                            sx={{
                                p: 2,
                                backgroundColor: getSeverityColor('critical'),
                                color: 'white',
                            }}
                        >
                            <Typography variant="h6">Critical</Typography>
                            <Typography variant="h3">
                                {countBySeverity('CRITICAL')}
                            </Typography>
                        </Paper>
                    </Grid>
                    <Grid item xs={12} md={3}>
                        <Paper
                            elevation={3}
                            sx={{
                                p: 2,
                                backgroundColor: getSeverityColor('high'),
                                color: 'white',
                            }}
                        >
                            <Typography variant="h6">High</Typography>
                            <Typography variant="h3">
                                {countBySeverity('HIGH')}
                            </Typography>
                        </Paper>
                    </Grid>
                    <Grid item xs={12} md={3}>
                        <Paper
                            elevation={3}
                            sx={{
                                p: 2,
                                backgroundColor: getSeverityColor('medium'),
                                color: 'white',
                            }}
                        >
                            <Typography variant="h6">Medium</Typography>
                            <Typography variant="h3">
                                {countBySeverity('MEDIUM')}
                            </Typography>
                        </Paper>
                    </Grid>
                    <Grid item xs={12} md={3}>
                        <Paper
                            elevation={3}
                            sx={{
                                p: 2,
                                backgroundColor: getSeverityColor('low'),
                                color: 'white',
                            }}
                        >
                            <Typography variant="h6">Low</Typography>
                            <Typography variant="h3">
                                {countBySeverity('LOW')}
                            </Typography>
                        </Paper>
                    </Grid>
                </Grid>
            </Box>

            {/* Controls */}
            <Box
                sx={{
                    mb: 3,
                    display: 'flex',
                    gap: 2,
                    alignItems: 'center',
                    flexWrap: 'wrap',
                }}
            >
                <FormControl sx={{ minWidth: 200 }}>
                    <InputLabel id="severity-filter-label">
                        Filter by Severity
                    </InputLabel>
                    <Select
                        labelId="severity-filter-label"
                        value={filterSeverity}
                        onChange={(e) => setFilterSeverity(e.target.value)}
                        label="Filter by Severity"
                    >
                        <MenuItem value="ALL">All Severities</MenuItem>
                        <MenuItem value="CRITICAL">Critical</MenuItem>
                        <MenuItem value="HIGH">High</MenuItem>
                        <MenuItem value="MEDIUM">Medium</MenuItem>
                        <MenuItem value="LOW">Low</MenuItem>
                    </Select>
                </FormControl>

                <FormControl sx={{ minWidth: 200 }}>
                    <InputLabel id="sort-by-label">Sort By</InputLabel>
                    <Select
                        labelId="sort-by-label"
                        value={sortBy}
                        onChange={(e) => setSortBy(e.target.value)}
                        label="Sort By"
                    >
                        <MenuItem value="severity">Severity</MenuItem>
                        {dataSource === 'grype' && (
                            <MenuItem value="risk">Risk Score</MenuItem>
                        )}
                        <MenuItem value="id">Vulnerability ID</MenuItem>
                        <MenuItem value="packageName">Package Name</MenuItem>
                    </Select>
                </FormControl>

                <Badge
                    badgeContent={vulnerabilitiesToFix.length}
                    color="primary"
                >
                    <Button
                        variant="outlined"
                        color="primary"
                        onClick={() => {
                            const element = document.getElementById('fix-list');
                            if (element)
                                element.scrollIntoView({ behavior: 'smooth' });
                        }}
                        disabled={vulnerabilitiesToFix.length === 0}
                    >
                        View Fix List
                    </Button>
                </Badge>
            </Box>

            {/* Results count */}
            <Typography variant="body2" sx={{ mb: 2 }}>
                Showing {filteredResults.length} of {results.length}{' '}
                vulnerabilities
            </Typography>

            {/* Display vulnerabilities by package */}
            {Object.entries(vulnerabilitiesByPackage).map(
                ([packageName, vulns], packageIndex) => (
                    <Card key={packageIndex} sx={{ mb: 2, boxShadow: 3 }}>
                        <CardContent sx={{ pb: 0 }}>
                            <Typography variant="h6" sx={{ fontWeight: 600 }}>
                                {packageName}
                                {vulns.length > 1 && (
                                    <Chip
                                        label={vulns.length}
                                        size="small"
                                        sx={{ ml: 1 }}
                                        color="primary"
                                    />
                                )}
                            </Typography>
                            <Box
                                sx={{
                                    mt: 1,
                                    display: 'flex',
                                    flexWrap: 'wrap',
                                    gap: 1,
                                }}
                            >
                                {vulns.map((vuln, i) => {
                                    const props = getVulnerabilityProps(
                                        vuln,
                                        dataSource
                                    );
                                    return (
                                        <Chip
                                            key={i}
                                            icon={getSeverityIcon(
                                                props.severity
                                            )}
                                            label={props.id}
                                            sx={{
                                                backgroundColor:
                                                    getSeverityColor(
                                                        props.severity
                                                    ),
                                                color: 'white',
                                                fontWeight: 'bold',
                                            }}
                                            onClick={() =>
                                                toggleExpand(
                                                    packageIndex + '-' + i
                                                )
                                            }
                                        />
                                    );
                                })}
                            </Box>
                        </CardContent>

                        {vulns.map((vuln, i) => {
                            const props = getVulnerabilityProps(
                                vuln,
                                dataSource
                            );
                            const isExpanded =
                                expandedIndex === packageIndex + '-' + i;

                            return (
                                <React.Fragment key={i}>
                                    <CardActions>
                                        <Button
                                            startIcon={
                                                isExpanded ? (
                                                    <ExpandLessIcon />
                                                ) : (
                                                    <ExpandMoreIcon />
                                                )
                                            }
                                            onClick={() =>
                                                toggleExpand(
                                                    packageIndex + '-' + i
                                                )
                                            }
                                            sx={{ textTransform: 'none' }}
                                        >
                                            {props.id} ({props.severity})
                                        </Button>
                                        <Box sx={{ ml: 'auto' }}>
                                            {isInFixList(props.id) ? (
                                                <Button
                                                    size="small"
                                                    variant="outlined"
                                                    color="error"
                                                    onClick={() =>
                                                        removeFromFixList(
                                                            props.id
                                                        )
                                                    }
                                                >
                                                    Remove from Fix List
                                                </Button>
                                            ) : (
                                                <Button
                                                    size="small"
                                                    variant="outlined"
                                                    color="primary"
                                                    onClick={() =>
                                                        addToFixList(vuln)
                                                    }
                                                >
                                                    Add to Fix List
                                                </Button>
                                            )}
                                        </Box>
                                    </CardActions>

                                    <Collapse
                                        in={isExpanded}
                                        timeout="auto"
                                        unmountOnExit
                                    >
                                        <CardContent>
                                            <TableContainer
                                                component={Paper}
                                                variant="outlined"
                                                sx={{ mb: 2 }}
                                            >
                                                <Table size="small">
                                                    <TableBody>
                                                        <TableRow>
                                                            <TableCell
                                                                component="th"
                                                                sx={{
                                                                    fontWeight:
                                                                        'bold',
                                                                    width: '30%',
                                                                }}
                                                            >
                                                                Vulnerability
                                                            </TableCell>
                                                            <TableCell>
                                                                {props.id}
                                                            </TableCell>
                                                        </TableRow>
                                                        <TableRow>
                                                            <TableCell
                                                                component="th"
                                                                sx={{
                                                                    fontWeight:
                                                                        'bold',
                                                                }}
                                                            >
                                                                Package
                                                            </TableCell>
                                                            <TableCell>
                                                                {
                                                                    props.packageName
                                                                }{' '}
                                                                {props.packageVersion &&
                                                                    `(${props.packageVersion})`}
                                                            </TableCell>
                                                        </TableRow>
                                                        <TableRow>
                                                            <TableCell
                                                                component="th"
                                                                sx={{
                                                                    fontWeight:
                                                                        'bold',
                                                                }}
                                                            >
                                                                Severity
                                                            </TableCell>
                                                            <TableCell>
                                                                <Chip
                                                                    label={
                                                                        props.severity
                                                                    }
                                                                    size="small"
                                                                    sx={{
                                                                        backgroundColor:
                                                                            getSeverityColor(
                                                                                props.severity
                                                                            ),
                                                                        color: 'white',
                                                                        fontWeight:
                                                                            'bold',
                                                                    }}
                                                                />
                                                            </TableCell>
                                                        </TableRow>
                                                        {dataSource ===
                                                            'grype' &&
                                                            props.risk !==
                                                                undefined && (
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Risk
                                                                        Score
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.risk.toFixed(
                                                                            6
                                                                        )}
                                                                    </TableCell>
                                                                </TableRow>
                                                            )}
                                                        <TableRow>
                                                            <TableCell
                                                                component="th"
                                                                sx={{
                                                                    fontWeight:
                                                                        'bold',
                                                                }}
                                                            >
                                                                Fixed Versions
                                                            </TableCell>
                                                            <TableCell>
                                                                {props.fixVersions &&
                                                                props
                                                                    .fixVersions
                                                                    .length > 0
                                                                    ? props.fixVersions.join(
                                                                          ', '
                                                                      )
                                                                    : 'No fix available'}
                                                            </TableCell>
                                                        </TableRow>
                                                        <TableRow>
                                                            <TableCell
                                                                component="th"
                                                                sx={{
                                                                    fontWeight:
                                                                        'bold',
                                                                }}
                                                            >
                                                                Description
                                                            </TableCell>
                                                            <TableCell>
                                                                {props.description ||
                                                                    'No description available'}
                                                            </TableCell>
                                                        </TableRow>
                                                        <TableRow>
                                                            <TableCell
                                                                component="th"
                                                                sx={{
                                                                    fontWeight:
                                                                        'bold',
                                                                }}
                                                            >
                                                                Data Source
                                                            </TableCell>
                                                            <TableCell>
                                                                {
                                                                    props.dataSource
                                                                }
                                                            </TableCell>
                                                        </TableRow>
                                                    </TableBody>
                                                </Table>
                                            </TableContainer>

                                            {/* CVSS score if available */}
                                            {props.cvss &&
                                                Object.keys(props.cvss).length >
                                                    0 && (
                                                    <React.Fragment>
                                                        <Typography
                                                            variant="subtitle1"
                                                            gutterBottom
                                                        >
                                                            CVSS Scores
                                                        </Typography>
                                                        <TableContainer
                                                            component={Paper}
                                                            variant="outlined"
                                                            sx={{ mb: 2 }}
                                                        >
                                                            <Table size="small">
                                                                <TableHead>
                                                                    <TableRow>
                                                                        <TableCell>
                                                                            Source
                                                                        </TableCell>
                                                                        <TableCell>
                                                                            Score
                                                                        </TableCell>
                                                                        <TableCell>
                                                                            Vector
                                                                        </TableCell>
                                                                    </TableRow>
                                                                </TableHead>
                                                                <TableBody>
                                                                    {Object.entries(
                                                                        props.cvss
                                                                    ).map(
                                                                        ([
                                                                            source,
                                                                            data,
                                                                        ]) => (
                                                                            <TableRow
                                                                                key={
                                                                                    source
                                                                                }
                                                                            >
                                                                                <TableCell>
                                                                                    {
                                                                                        source
                                                                                    }
                                                                                </TableCell>
                                                                                <TableCell>
                                                                                    {data.V3Score ||
                                                                                        'N/A'}
                                                                                </TableCell>
                                                                                <TableCell>
                                                                                    {data.V3Vector ||
                                                                                        'N/A'}
                                                                                </TableCell>
                                                                            </TableRow>
                                                                        )
                                                                    )}
                                                                </TableBody>
                                                            </Table>
                                                        </TableContainer>
                                                    </React.Fragment>
                                                )}

                                            {/* References if available */}
                                            {props.references &&
                                                props.references.length > 0 && (
                                                    <React.Fragment>
                                                        <Typography
                                                            variant="subtitle1"
                                                            gutterBottom
                                                        >
                                                            References
                                                        </Typography>
                                                        <Box
                                                            sx={{
                                                                maxHeight:
                                                                    '200px',
                                                                overflow:
                                                                    'auto',
                                                                mb: 2,
                                                            }}
                                                        >
                                                            <ul
                                                                style={{
                                                                    paddingLeft:
                                                                        '20px',
                                                                }}
                                                            >
                                                                {props.references.map(
                                                                    (
                                                                        ref,
                                                                        i
                                                                    ) => (
                                                                        <li
                                                                            key={
                                                                                i
                                                                            }
                                                                        >
                                                                            <Link
                                                                                href={
                                                                                    ref
                                                                                }
                                                                                target="_blank"
                                                                                rel="noopener noreferrer"
                                                                                sx={{
                                                                                    wordBreak:
                                                                                        'break-all',
                                                                                }}
                                                                            >
                                                                                {
                                                                                    ref
                                                                                }
                                                                            </Link>
                                                                        </li>
                                                                    )
                                                                )}
                                                            </ul>
                                                        </Box>
                                                    </React.Fragment>
                                                )}
                                        </CardContent>
                                    </Collapse>
                                </React.Fragment>
                            );
                        })}
                    </Card>
                )
            )}

            {/* Fix List Section */}
            {vulnerabilitiesToFix.length > 0 && (
                <Box id="fix-list" sx={{ mt: 5 }}>
                    <Typography
                        variant="h4"
                        gutterBottom
                        sx={{ fontWeight: 600, color: '#1a237e', mb: 2 }}
                    >
                        Fix Priority List
                    </Typography>
                    <Paper elevation={3} sx={{ p: 3 }}>
                        <TableContainer>
                            <Table>
                                <TableHead>
                                    <TableRow>
                                        <TableCell>Vulnerability ID</TableCell>
                                        <TableCell>Package</TableCell>
                                        <TableCell>Severity</TableCell>
                                        <TableCell>Fixed Version</TableCell>
                                        <TableCell>Action</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {vulnerabilitiesToFix
                                        .sort((a, b) => {
                                            const severityOrder = {
                                                CRITICAL: 4,
                                                HIGH: 3,
                                                MEDIUM: 2,
                                                LOW: 1,
                                                UNKNOWN: 0,
                                            };
                                            const severityA =
                                                severityOrder[
                                                    a.severity?.toUpperCase()
                                                ] || 0;
                                            const severityB =
                                                severityOrder[
                                                    b.severity?.toUpperCase()
                                                ] || 0;
                                            return severityB - severityA;
                                        })
                                        .map((vuln, index) => (
                                            <TableRow key={index}>
                                                <TableCell>{vuln.id}</TableCell>
                                                <TableCell>
                                                    {vuln.packageName}{' '}
                                                    {vuln.packageVersion &&
                                                        `(${vuln.packageVersion})`}
                                                </TableCell>
                                                <TableCell>
                                                    <Chip
                                                        label={vuln.severity}
                                                        size="small"
                                                        sx={{
                                                            backgroundColor:
                                                                getSeverityColor(
                                                                    vuln.severity
                                                                ),
                                                            color: 'white',
                                                            fontWeight: 'bold',
                                                        }}
                                                    />
                                                </TableCell>
                                                <TableCell>
                                                    {vuln.fixVersions &&
                                                    vuln.fixVersions.length > 0
                                                        ? vuln.fixVersions.join(
                                                              ', '
                                                          )
                                                        : 'No fix available'}
                                                </TableCell>
                                                <TableCell>
                                                    <Button
                                                        size="small"
                                                        variant="outlined"
                                                        color="error"
                                                        onClick={() =>
                                                            removeFromFixList(
                                                                vuln.id
                                                            )
                                                        }
                                                    >
                                                        Remove
                                                    </Button>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </Paper>
                </Box>
            )}
        </Container>
    );
}
