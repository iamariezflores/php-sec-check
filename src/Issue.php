<?php

namespace Aquilinoflores\PhpSecCheck;

/**
 * Historical name for a Finding.
 *
 * Checks still construct Issue objects. New code should type-hint Finding.
 */
class Issue extends Finding
{
}
