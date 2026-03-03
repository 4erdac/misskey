/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

export class AddOidcRegistration1770454601174 {
    name = 'AddOidcRegistration1770454601174'

    /**
     * @param {QueryRunner} queryRunner
     */
    async up(queryRunner) {
        await queryRunner.query(`CREATE TABLE "oidc_registration" ("id" character varying(32) NOT NULL, "userId" character varying(32) NOT NULL, "sub" character varying(256) NOT NULL, "issuer" character varying(512) NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL, "lastUsedAt" TIMESTAMP WITH TIME ZONE NOT NULL, CONSTRAINT "PK_oidc_registration_id" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_oidc_registration_userId" ON "oidc_registration" ("userId") `);
        await queryRunner.query(`CREATE INDEX "IDX_oidc_registration_sub" ON "oidc_registration" ("sub") `);
        await queryRunner.query(`CREATE UNIQUE INDEX "IDX_oidc_registration_issuer_sub" ON "oidc_registration" ("issuer", "sub") `);
        await queryRunner.query(`COMMENT ON COLUMN "oidc_registration"."sub" IS 'OIDC subject identifier'`);
        await queryRunner.query(`COMMENT ON COLUMN "oidc_registration"."issuer" IS 'OIDC issuer identifier'`);
        await queryRunner.query(`COMMENT ON COLUMN "oidc_registration"."createdAt" IS 'First linked at'`);
        await queryRunner.query(`COMMENT ON COLUMN "oidc_registration"."lastUsedAt" IS 'Last used at'`);
        await queryRunner.query(`ALTER TABLE "oidc_registration" ADD CONSTRAINT "FK_oidc_registration_userId" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    /**
     * @param {QueryRunner} queryRunner
     */
    async down(queryRunner) {
        await queryRunner.query(`ALTER TABLE "oidc_registration" DROP CONSTRAINT "FK_oidc_registration_userId"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_oidc_registration_issuer_sub"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_oidc_registration_sub"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_oidc_registration_userId"`);
        await queryRunner.query(`DROP TABLE "oidc_registration"`);
    }
}
