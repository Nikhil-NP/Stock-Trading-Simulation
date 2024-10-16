# Stock Trading Simulation

A web-based stock trading simulation platform built with Flask, implementing the CS50x Finance project specifications. This application enables users to manage virtual stock portfolios using real-time market data.

## Overview

The application provides a simulated trading environment where users can:
- Manage virtual investment portfolios
- Execute mock stock trades
- Track real-time stock values
- Monitor transaction history
- Analyze portfolio performance

## Features

- User authentication system
- Real-time stock quotes via IEX Cloud API
- Virtual trading with $10,000 starting capital
- Portfolio management dashboard
- Transaction logging and history
- Responsive web interface

## Technical Stack

- Python/Flask
- SQLite Database
- HTML/CSS/JavaScript
- Bootstrap Framework
- IEX Cloud API Integration

## Installation

```bash
git clone [repository-url]
cd stock-trading-simulation
pip install -r requirements.txt
export API_KEY=your_iex_cloud_api_key
flask run
```

## Project Structure

- `/static` - CSS and JavaScript assets
- `/templates` - HTML templates
- `app.py` - Main application logic
- `helpers.py` - Utility functions
- `finance.db` - SQLite database

## Implementation Notes

This project was developed as part of Harvard's CS50x coursework, implementing core trading functionalities while maintaining security and efficiency. The system uses real-time data to simulate market conditions and trading mechanics.

## Credits

Developed as part of Harvard University's CS50x curriculum.
API services provided by IEX Cloud.