<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\HttpClientInterface;

class AnomalyDetectionService
{
    private HttpClientInterface $client;

    public function __construct(
        HttpClientInterface $client
    ) {
        $this->client = $client;
    }

    public function analyzeCase(array $case): ?array
    {
        try {
            $response = $this->client->request(
                'POST',
                'http://127.0.0.1:8000/api/apurement/analyze',
                [
                    'json' => [
                        'data' => $case,

                        'options' => [
                            "controle_champs_obligatoires" => True,
                            "controle_logique_conditionnelle" => True,
                            "controle_dates" => True,
                            "controle_gps"=> True,
                            "controle_montants" => True,
                            "controle_q2_q3"=>True
                        ]
                    ],

                    'timeout' => 10,
                ]
            );

            return $response->toArray();
           ;
        } catch (\Throwable $e) {

            error_log(
                '[APUREMENT] Erreur FastAPI : '
                . $e->getMessage()
            );

            return null;
        }
    }
}