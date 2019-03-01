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

namespace EasyTOTP\Tests;

use EasyOTP\TimeService;
use EasyOTP\TOTP;
use EasyOTP\TOTPInterface;
use EasyOTP\TOTPValidResultInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Otp test case.
 */
class TOTPTest extends TestCase
{
	/** @var string */
	private $secret = "12345678901234567890";

	/** @var TimeService|MockObject */
	private $timeService;

	/**
	 * Prepares the environment before running a test.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->timeService = $this->createMock(TimeService::class);
	}

	/**
	 * Invalid counter values for tests
	 */
	public function totpTestValues()
	{
		return [
			[59, '94287082', TOTPInterface::HASH_SHA1],
			//[59, '46119246', TOTPInterface::HASH_SHA256],
			//[59, 90693936, TOTPInterface::HASH_SHA512],
			[1111111109, '07081804', TOTPInterface::HASH_SHA1],
			//[1111111109, '68084774', TOTPInterface::HASH_SHA256],
			//[1111111109, '25091201', TOTPInterface::HASH_SHA512],
			[1111111111, '14050471', TOTPInterface::HASH_SHA1],
			//[1111111111, '67062674', TOTPInterface::HASH_SHA256],
			//[1111111111, '99943326', TOTPInterface::HASH_SHA512],
			[1234567890, '89005924', TOTPInterface::HASH_SHA1],
			//[1234567890, '91819424', TOTPInterface::HASH_SHA256],
			//[1234567890, '93441116', TOTPInterface::HASH_SHA512],
			[2000000000, '69279037', TOTPInterface::HASH_SHA1],
			//[2000000000, '90698825', TOTPInterface::HASH_SHA256],
			//[2000000000, '38618901', TOTPInterface::HASH_SHA512],
			[20000000000, '65353130', TOTPInterface::HASH_SHA1],
			//[20000000000, '77737706', TOTPInterface::HASH_SHA256],
			//[20000000000, '47863826', TOTPInterface::HASH_SHA512],
		];
	}

	/**
	 * @dataProvider totpTestValues
	 *
	 * @param int $time
	 * @param string $otp
	 * @param string $hashFunction
	 */
	public function testTOTPRFC(int $time, string $otp, string $hashFunction) {
		$this->timeService->method('getTime')
			->willReturn($time);

		$totp = new TOTP(
			$this->secret,
			30,
			8,
			0,
			$hashFunction,
			$this->timeService);

		$result = $totp->verify($otp, 0, 0);
		$this->assertInstanceOf(TOTPValidResultInterface::class, $result);
	}
}
