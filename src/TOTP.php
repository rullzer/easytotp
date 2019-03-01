<?php
declare(strict_types=1);
/**
 * @copyright Copyright (c) 2019, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace EasyOTP;

class TOTP implements TOTPInterface  {

	/** @var string */
	private $secret;
	/** @var int */
	private $digits;
	/** @var int */
	private $offset;
	/** @var int */
	private $timeStep;
	/** @var string */
	private $hashFunction;
	/** @var TimeService */
	private $timeService;

	public function __construct(string $secret, int $timeStep, int $digits, int $offset, string $hashFunction, TimeService $timeService) {
		$this->secret = $secret;
		$this->timeStep = $timeStep;
		$this->digits = $digits;
		$this->offset = $offset;
		$this->hashFunction = $hashFunction;
		$this->timeService = $timeService;
	}

	public function verify(string $otp, int $drift = 1, int $minCounter = 0): TOTPResultInterface {
		$currentCounter = $this->getCurrentCounter();

		$start = $currentCounter - $drift;
		$end = $currentCounter + $drift;

		for ($i = $start; $i <= $end; $i++) {
			// Skip counters smaller than the minimum
			if ($i < $minCounter) {
				continue;
			}

			if (hash_equals($this->hotp($i), $otp)) {
				return new TOTPValidResult(
					$i,
					$i - $currentCounter
				);
			}
		}

		return new TOTPInvalidResult();
	}

	public function getDigits(): int {
		return $this->digits;
	}

	public function getHashFunction(): string {
		return $this->hashFunction;
	}

	public function getOffset(): int {
		return $this->offset;
	}

	public function getSecret(): string {
		return $this->secret;
	}

	public function getTimeStep(): int {
		return $this->timeStep;
	}

	/**
	 * See https://tools.ietf.org/html/rfc4226#section-5
	 */
	private function hotp(int $counter): string {
		$hash = hash_hmac(
			$this->hashFunction,
			pack('J', $counter),
			$this->prepareSecret(),
			true
		);

		return str_pad((string)$this->truncate($hash), $this->digits, '0', STR_PAD_LEFT);
	}

	private function prepareSecret() {
		$secretLength = 20;
		if ($this->hashFunction === TOTPInterface::HASH_SHA256) {
			$secretLength = 32;
		}
		if ($this->hashFunction === TOTPInterface::HASH_SHA512) {
			$secretLength = 64;
		}

		$secret = $this->secret;

		while(strlen($secret) < $secretLength) {
			$secret .= $secret;
		}

		$secret = substr($secret, 0, $secretLength);
		return $secret;
	}

	private function truncate(string $hash): int {
		$offset = \ord($hash[strlen($hash)-1]) & 0xf;

		return (
				((\ord($hash[$offset + 0]) & 0x7f) << 24) |
				((\ord($hash[$offset + 1]) & 0xff) << 16) |
				((\ord($hash[$offset + 2]) & 0xff) << 8) |
				(\ord($hash[$offset + 3]) & 0xff)
			) % (10 ** $this->digits);
	}

	private function getCurrentCounter(): int {
		return (int)floor(($this->timeService->getTime() + $this->offset) / $this->timeStep);
	}

}
