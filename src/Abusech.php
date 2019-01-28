<?php

namespace AbuseIO\Collectors;

use AbuseIO\Models\Incident;
use Validator;
use AbuseIO\Models\Ticket;
use Ddeboer\DataImport\Reader;
use Carbon;

/**
 * Class Abusech
 * @package AbuseIO\Collectors
 */
class Abusech extends Collector
{
    /**
     * A value to store the generic configuration after validations passed.
     *
     * @var array
     */
    private $config = [ ];

    /**
     * A value to store the feed configuration after validations passed.
     *
     * @var array
     */
    private $feeds = [ ];

    private $feedName;
    private $feedConfig;

    /**
     * The validations for each feed
     *
     * @var array
     */
    protected $rulesFeed = [
        'APIurl'        => 'required|string',
        'class'         => 'required|abuseclass',
        'type'          => 'required|abusetype',
        'enabled'       => 'required|boolean',
        'fields'        => 'sometimes|array',
        'filters'       => 'sometimes|array',
    ];

    /**
     * Create a new Abusehub instance
     *
     */
    public function __construct()
    {
        // Call the parent constructor to initialize some basics
        parent::__construct($this);
    }

    /**
     * Fetch AbuseCH data
     *
     * @return array    Returns array with failed or success data
     *                  (See collector-common/src/Collector.php) for more info.
     */
    public function parse()
    {
        /*
         * Preflight validations
         */
        $this->config = config("{$this->configBase}.collector");
        $this->feeds = config("{$this->configBase}.feeds");

        if (empty($this->feeds) || !is_array($this->feeds)) {
            return $this->failed('No feeds configured, or feed config invalid');
        }

        foreach ($this->feeds as $feedName => $feedConfig) {
            $this->feedName = $feedName;
            $this->feedConfig = $feedConfig;

            $validator = Validator::make(
                array_merge($feedConfig, ['name' => $feedName]),
                $this->rulesFeed
            );

            if ($validator->fails()) {
                return $this->failed(implode(' ', $validator->messages()->all()));
            }

            foreach($this->config['asns'] as $asn) {
                $url = "{$feedConfig['APIurl']}/feeds/asn/{$asn}";

                $this->parseRequest($url);
            }
        }

        return $this->success();
    }

    /**
     * Do the API request collecting the data for the ASN
     * @internal: It might work?
     *
     * @param array $asns
     * @return array $scanResult
     */
    private function apiRequest($url)
    {
        $ch = curl_init(); 

        curl_setopt($ch, CURLOPT_URL, $url); 
        $agent= 'AbuseIO (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322)'; 
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); 
        curl_setopt($ch, CURLOPT_VERBOSE, false); 
        curl_setopt($ch, CURLOPT_USERAGENT, $agent); 
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15); //time out of 15 seconds
        $apiData = curl_exec($ch); 

        curl_close($ch);

        return $apiData;
    }

    /**
     * Parse the API results for the ASN
     * @internal: It might work?
     *
     * @param string $url
     * @return boolean $success
     */
    private function parseData($url)
    {
        $scanResult = [];

        $csv = $this->apiResult($url);
        $csv = substr($csv, strpos('Dateadded', $csv));
        $csv = preg_replace('/^#.*$/', '', $csv);

        if (!$this->createWorkingDir()) {
            return $this->failed(
                "Unable to create working directory"
            );
        }

        $tempFile = $this->tempPath . 'data.csv';
        file_put_contents($tempFile, $csv);

        $csvReports = new Reader\CsvReader(
             new SplFileObject($this->tempPath . $compressedFile)
        );
        $csvReports->setHeaderRowNumber(0);
        foreach ($csvReports as $report) {
            $incident = new Incident();
            $incident->source      = $feedName;
            $incident->source_id   = false;
            $incident->ip          = $report['IPaddress'];
            $incident->domain      = $report['Host'];
            $incident->class       = $this->feedConfig['class'];
            $incident->type        = $this->feedConfig['type'];

            /*
             * today's timestamp used as report time (today 00:00) to prevent a lot of duplicates on the
             * same day. Using the same time will aggregate and deduplicate events into 1 per day.
             */
            $incident->timestamp   = Carbon::today()->timestamp;

            $incident->information = json_encode(
                array_merge(
                    $feedData['information'],
                    [
                        'Added on' => $report['Dateadded (UTC)'],
                        'Threat'   => $report['Threat'],
                    ]
                )
            );

            $this->incidents[] = $incident;
        }

        return true;
    }
}
