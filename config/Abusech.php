<?php
/*
 *
 */
return [
    'collector' => [
        'name'          => 'AbuseCH collector',
        'description'   => 'Collects data from AbuseCH to generate events',
        'enabled'       => false,

        'asns'          => [
            '20857'
        ],

    ],

    /*
     */
    'feeds' => [
        'URLhaus' => [
            'APIurl'    => 'https://urlhaus.abuse.ch/feeds',
            'class'     => 'COMPROMISED_WEBSITE',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                //
            ],
            'filters'   => [
                //
            ],
        ],
    ],
];
