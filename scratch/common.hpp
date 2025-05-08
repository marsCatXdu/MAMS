#pragma once
#include <cmath>
#include <utility>
#include <algorithm>

struct LinkParams {
    double txPower_dBm;      // Transmit power (dBm)
    double bwHz;             // Bandwidth (Hz)
    double eta;              // Implementation loss (0<η≤1)
    double beta;             // Path‑loss exponent
    double noiseFloor_dBm;   // Noise power density integrated over bw (dBm)
    double interference_dBm; // Aggregate interference (dBm)
    double coverage_m;       // Max service range
    double x_tx;             // Transmitter position on the road (m)
};

// ---------- helpers ----------
constexpr double dBm_to_mW(double dBm)   { return std::pow(10.0, dBm / 10.0); }
constexpr double mW_to_dBm(double mW)    { return 10.0 * std::log10(mW); }
constexpr double log2p1(double x)        { return std::log2(1.0 + x); }

// Eq. 15 & 16 folded together
inline double capacity_Mbps(double x_ue, const LinkParams& p)
{
    const double d = std::fabs(x_ue - p.x_tx);
    if (d > p.coverage_m) return 0.0;               // outside coverage → no service

    // received power after log‑distance path loss (d>1 m to avoid log(0))
    const double Prx_dBm = p.txPower_dBm - 10.0 * p.beta * std::log10(std::max(d, 1.0));
    const double Prx_mW  = dBm_to_mW(Prx_dBm);

    const double N_mW    = dBm_to_mW(p.noiseFloor_dBm);
    const double I_mW    = dBm_to_mW(p.interference_dBm);
    const double sinr    = Prx_mW / (N_mW + I_mW);  // Eq 16

    const double cap_bps = p.eta * p.bwHz * log2p1(sinr); // Eq 15
    return cap_bps / 1e6;                                // → Mbit/s
}

// convenience wrapper to get both links in one call
inline std::pair<double,double> capacity_wifi_lte(double x_ue)
{
    static const LinkParams wifi {
        /*tx*/20, /*bwHz*/40e4, /*eta*/0.7, /*beta*/2.2,
        /*N*/-100, /*I*/-95, /*cov*/200, /*x_tx*/0
    };
    static const LinkParams lte {
        /*tx*/43, /*bwHz*/30e4, /*eta*/0.7, /*beta*/2.8,
        /*N*/-100, /*I*/-95, /*cov*/400, /*x_tx*/400
    };

    return { capacity_Mbps(x_ue, wifi), capacity_Mbps(x_ue, lte) };
}
